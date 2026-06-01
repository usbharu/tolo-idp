package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditLogRepository
import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Principal
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@SpringBootTest
@AutoConfigureMockMvc
class TokenExchangeEndpointTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val authorizationService: OAuth2AuthorizationService,
    @Autowired private val registeredClientRepository: RegisteredClientRepository,
    @Autowired private val passwordEncoder: PasswordEncoder,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val auditLogRepository: AuditLogRepository,
    @Autowired private val jtiDenylistRepository: JtiDenylistRepository,
    @Autowired private val clientPolicyRepository: ClientPolicyRepository,
    @Autowired private val jdbcClient: JdbcClient,
    @Autowired private val jwtDecoder: JwtDecoder,
) {
    @BeforeEach
    fun setUp() {
        jdbcClient.sql("delete from oauth2_authorization").update()
        auditLogRepository.deleteAll()
        jtiDenylistRepository.deleteAll()
        cacheRepository.deleteAll()
        ensurePublicPolicyClient()
        cacheRepository.put(
            tenantId = "tenant-a",
            userId = "user-123",
            membership = TenantMembership(
                tenantId = "tenant-a",
                tenantRole = RelationRole.OWNER,
                events = listOf(
                    EventMembership("event-1", RelationRole.OWNER),
                    EventMembership("event-staff", RelationRole.STAFF),
                ),
            ),
            cachedAt = Instant.EPOCH,
            expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
        )
    }

    @Test
    fun exchangesTenantAccessTokenForEventAccessJwtAndRecordsSuccessAudit() {
        val subjectToken = saveTenantAuthorization()

        val result = mockMvc.perform(tokenExchangeRequest(subjectToken))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andExpect(jsonPath("$.issued_token_type").value(ACCESS_TOKEN_TYPE))
            .andExpect(jsonPath("$.scope").value("events.read"))
            .andReturn()

        val accessToken = Regex(""""access_token"\s*:\s*"([^"]+)"""")
            .find(result.response.contentAsString)
            ?.groupValues
            ?.get(1)
        assertNotNull(accessToken)
        val jwt = jwtDecoder.decode(accessToken)
        assertEquals(TOKEN_USE_EVENT_ACCESS, jwt.claims["token_use"])
        assertEquals("tenant-a", jwt.claims["tenant_id"])
        assertEquals("event-1", jwt.claims["event_id"])
        assertEquals("https://api.example.com/tenants/tenant-a/events/event-1", jwt.claims["resource"])
        assertEquals(listOf("backend-api"), jwt.audience)
        assertEquals("events.read", jwt.claims["scope"])

        val audit = latestAudit()
        assertEquals("success", audit["result"])
        assertEquals("client-123", audit["client_id"])
        assertEquals("user-123", audit["subject"])
        assertEquals(TOKEN_USE_TENANT_ACCESS, audit["source_token_use"])
        assertEquals(TOKEN_USE_EVENT_ACCESS, audit["requested_token_use"])
        assertEquals("tenant-a", audit["tenant_id"])
        assertEquals("event-1", audit["event_id"])
        assertEquals("events.read", audit["issued_scope"])
        assertNotNull(audit["issued_jti"])
    }

    @Test
    fun rejectsPublicClientTokenExchangeAndRecordsFailureAudit() {
        val subjectToken = saveTenantAuthorization()

        mockMvc.perform(
            tokenExchangeRequest(
                subjectToken = subjectToken,
                clientId = PUBLIC_POLICY_CLIENT_ID,
                clientSecret = PUBLIC_POLICY_CLIENT_SECRET,
            ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        assertEquals("client_not_allowed", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsAudienceOutsideClientPolicyAsInvalidTarget() {
        val subjectToken = saveTenantAuthorization()

        mockMvc.perform(tokenExchangeRequest(subjectToken = subjectToken, audience = "other-api"))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_target"))

        assertEquals("audience_not_allowed", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsInvalidEventResourceAsInvalidTarget() {
        val subjectToken = saveTenantAuthorization()

        mockMvc.perform(tokenExchangeRequest(subjectToken = subjectToken, resource = "https://api.example.com/tenants/tenant-a"))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_target"))

        assertEquals("resource_invalid_format", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsScopeNotAllowedForClientAsInvalidScope() {
        val subjectToken = saveTenantAuthorization()

        mockMvc.perform(tokenExchangeRequest(subjectToken = subjectToken, scope = "admin.read"))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_scope"))

        assertEquals("scope_not_allowed_for_client", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsScopeExceedingSubjectTokenAsInvalidGrant() {
        val subjectToken = saveTenantAuthorization(scopes = setOf("events.read"))

        mockMvc.perform(tokenExchangeRequest(subjectToken = subjectToken, scope = "events.write"))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        assertEquals("scope_exceeds_subject_token", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsWriteScopeForStaffEventMemberAsInvalidScope() {
        val subjectToken = saveTenantAuthorization()

        mockMvc.perform(
            tokenExchangeRequest(
                subjectToken = subjectToken,
                resource = "https://api.example.com/tenants/tenant-a/events/event-staff",
                scope = "events.write",
            ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_scope"))

        assertEquals("scope_not_allowed_for_role", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsEventTokenAsSubjectAsInvalidGrant() {
        val subjectToken = saveTenantAuthorization(tokenUse = TOKEN_USE_EVENT_ACCESS)

        mockMvc.perform(tokenExchangeRequest(subjectToken))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        assertEquals("invalid_token_use_transition", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsTenantMismatchAsInvalidGrant() {
        val subjectToken = saveTenantAuthorization(tenantId = "tenant-b")

        mockMvc.perform(tokenExchangeRequest(subjectToken))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        assertEquals("event_not_in_tenant", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsDeniedSubjectTokenAsInvalidGrant() {
        val subjectToken = saveTenantAuthorization(jti = "denied-jti")
        jtiDenylistRepository.save(
            JtiDenylistEntry("denied-jti", Instant.parse("2030-01-01T00:00:00Z"))
                .apply { isNewEntity = true },
        )

        mockMvc.perform(tokenExchangeRequest(subjectToken))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))

        assertEquals("token_revoked", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsMissingEventMembershipAsInvalidGrantWithoutLeakingDetailsInErrorCode() {
        val subjectToken = saveTenantAuthorization()

        mockMvc.perform(
            tokenExchangeRequest(
                subjectToken = subjectToken,
                resource = "https://api.example.com/tenants/tenant-a/events/event-missing",
            ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
            .andExpect(jsonPath("$.error_description").doesNotExist())

        assertEquals("user_not_event_member", latestAudit()["failure_reason"])
    }

    @Test
    fun rejectsUnsupportedSubjectTokenTypeAsInvalidRequest() {
        val subjectToken = saveTenantAuthorization()

        mockMvc.perform(
            tokenExchangeRequest(subjectToken = subjectToken)
                .param("subject_token_type", "urn:example:unsupported"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
    }

    private fun tokenExchangeRequest(
        subjectToken: String,
        clientId: String = "client-123",
        clientSecret: String = "secret",
        audience: String = "backend-api",
        resource: String = "https://api.example.com/tenants/tenant-a/events/event-1",
        scope: String = "events.read",
    ) =
        post("/oauth2/token")
            .with(httpBasic(clientId, clientSecret))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("grant_type", AuthorizationGrantType.TOKEN_EXCHANGE.value)
            .param("subject_token", subjectToken)
            .param("subject_token_type", ACCESS_TOKEN_TYPE)
            .param("audience", audience)
            .param("resource", resource)
            .param("scope", scope)

    private fun saveTenantAuthorization(
        tokenUse: String = TOKEN_USE_TENANT_ACCESS,
        tenantId: String = "tenant-a",
        scopes: Set<String> = setOf("tenant.read", "events.read", "events.write"),
        jti: String = "jti-${UUID.randomUUID()}",
    ): String {
        val tokenValue = "subject-token-${UUID.randomUUID()}"
        val registeredClient = registeredClientRepository.findByClientId("client-123")
            ?: error("seed client-123 is required")
        val authentication = UsernamePasswordAuthenticationToken.authenticated(
            "user-123",
            null,
            listOf(SimpleGrantedAuthority("ROLE_USER")),
        )
        val now = Instant.now()
        val token = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            tokenValue,
            now.minusSeconds(60),
            now.plusSeconds(3600),
            scopes,
        )
        val authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName("user-123")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(scopes)
            .attribute(Principal::class.java.name, authentication)
            .token(token) { metadata ->
                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = mapOf(
                    "iss" to "http://localhost:8080",
                    "sub" to "user-123",
                    "aud" to listOf("backend-api"),
                    "client_id" to "client-123",
                    "scope" to scopes.joinToString(" "),
                    "token_use" to tokenUse,
                    "resource" to "https://api.example.com/tenants/$tenantId",
                    "tenant_id" to tenantId,
                    "iat" to now.minusSeconds(60),
                    "nbf" to now.minusSeconds(60),
                    "exp" to now.plusSeconds(3600),
                    "jti" to jti,
                )
            }
            .build()
        authorizationService.save(authorization)
        return tokenValue
    }

    private fun latestAudit(): Map<String, Any?> =
        auditLogRepository.findAll()
            .maxBy { it.id ?: 0 }
            .let {
                mapOf(
                    "client_id" to it.clientId,
                    "subject" to it.subject,
                    "source_token_use" to it.sourceTokenUse,
                    "requested_token_use" to it.requestedTokenUse,
                    "requested_audience" to it.requestedAudience,
                    "requested_resource" to it.requestedResource,
                    "requested_scope" to it.requestedScope,
                    "issued_scope" to it.issuedScope,
                    "tenant_id" to it.tenantId,
                    "event_id" to it.eventId,
                    "result" to it.result,
                    "failure_reason" to it.failureReason,
                    "issued_jti" to it.issuedJti,
                )
            }

    private fun ensurePublicPolicyClient() {
        if (registeredClientRepository.findByClientId(PUBLIC_POLICY_CLIENT_ID) == null) {
            registeredClientRepository.save(
                RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(PUBLIC_POLICY_CLIENT_ID)
                    .clientSecret(passwordEncoder.encode(PUBLIC_POLICY_CLIENT_SECRET))
                    .clientName("Public token exchange test client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .build(),
            )
        }
        clientPolicyRepository.save(
            ClientPolicy(
                clientId = PUBLIC_POLICY_CLIENT_ID,
                clientType = ClientType.PUBLIC,
                allowedGrantTypes = setOf(AuthorizationGrantType.TOKEN_EXCHANGE.value),
                allowedTransitions = setOf(TOKEN_EXCHANGE_TRANSITION_TENANT_TO_EVENT),
                allowedAudiences = setOf("backend-api"),
                allowedScopes = setOf("tenant.read", "events.read", "events.write"),
                tenantAccessTtl = java.time.Duration.ofSeconds(900),
                eventAccessTtl = java.time.Duration.ofSeconds(600),
            ),
        )
    }

    private companion object {
        const val PUBLIC_POLICY_CLIENT_ID = "public-token-exchange-client"
        const val PUBLIC_POLICY_CLIENT_SECRET = "public-secret"
    }
}
