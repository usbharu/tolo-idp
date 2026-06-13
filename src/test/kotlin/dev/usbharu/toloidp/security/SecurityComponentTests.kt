package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.scope.ScopePolicy
import dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import java.time.Duration
import java.time.Instant
import kotlin.test.AfterTest
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@SpringBootTest
class SecurityComponentTests(
    @Autowired private val registeredClientRepository: RegisteredClientRepository,
    @Autowired private val clientPolicyRepository: ClientPolicyRepository,
    @Autowired private val resourceParser: ResourceParser,
    @Autowired private val relationService: RelationService,
    @Autowired private val scopePolicy: ScopePolicy,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val jwtCustomizer: ToloJwtCustomizer,
) {
    private lateinit var registeredClient: RegisteredClient
    private val principal = UsernamePasswordAuthenticationToken.authenticated(
        "user-123",
        null,
        listOf(SimpleGrantedAuthority("ROLE_USER")),
    )

    @BeforeEach
    fun setUp() {
        registeredClient = registeredClientRepository.findByClientId("client-123")
            ?: error("seed client-123 is required")
        replaceClientPolicy()
        AuthorizationServerContextHolder.setContext(
            object : AuthorizationServerContext {
                private val settings = AuthorizationServerSettings.builder().issuer("http://localhost:8080").build()

                override fun getIssuer(): String = "http://localhost:8080"

                override fun getAuthorizationServerSettings(): AuthorizationServerSettings = settings
            },
        )
        cacheRepository.deleteAll()
        cacheMembership(
            TenantMembership(
                tenantId = "tenant-a",
                tenantRole = RelationRole.OWNER,
                events = listOf(EventMembership("event-1", RelationRole.STAFF)),
            ),
        )
    }

    @AfterTest
    fun tearDown() {
        SecurityContextHolder.clearContext()
        AuthorizationServerContextHolder.resetContext()
    }

    @Test
    fun tenantAwareAuthorizationRequestConverterAddsSessionTenantResource() {
        SecurityContextHolder.getContext().authentication = principal
        val request = authorizationRequest()
        request.getSession(true)!!.setAttribute(SELECTED_TENANT_SESSION_ATTRIBUTE, "tenant-a")

        val converted = TenantAwareAuthorizationRequestConverter(resourceParser).convert(request)
            as OAuth2AuthorizationCodeRequestAuthenticationToken

        assertEquals("client-123", converted.clientId)
        assertEquals(
            "https://api.example.com/tenants/tenant-a",
            converted.additionalParameters[OAuth2ParameterNames.RESOURCE],
        )
    }

    @Test
    fun tenantAwareAuthorizationRequestConverterLeavesRequestUnchangedWithoutSessionTenant() {
        SecurityContextHolder.getContext().authentication = principal
        val request = authorizationRequest()

        val converted = TenantAwareAuthorizationRequestConverter(resourceParser).convert(request)
            as OAuth2AuthorizationCodeRequestAuthenticationToken

        assertFalse(converted.additionalParameters.containsKey(OAuth2ParameterNames.RESOURCE))
    }

    @Test
    fun tenantAuthorizationValidatorAcceptsAllowedTenantRequest() {
        val validator = TenantAuthorizationValidator(clientPolicyRepository, resourceParser, relationService, scopePolicy)

        validator.accept(authorizationContext(scopes = setOf("tenant.read", "events.read")))
    }

    @Test
    fun tenantAuthorizationValidatorRejectsClientPolicyWithoutAuthorizationCodeGrant() {
        replaceClientPolicy(allowedGrantTypes = setOf(AuthorizationGrantType.TOKEN_EXCHANGE.value))
        val validator = TenantAuthorizationValidator(clientPolicyRepository, resourceParser, relationService, scopePolicy)

        val exception = assertFailsWith<OAuth2AuthorizationCodeRequestAuthenticationException> {
            validator.accept(authorizationContext(scopes = setOf("tenant.read")))
        }

        assertEquals("unauthorized_client", exception.error.errorCode)
    }

    @Test
    fun tenantAuthorizationValidatorRejectsAudienceOutsidePolicy() {
        val validator = TenantAuthorizationValidator(clientPolicyRepository, resourceParser, relationService, scopePolicy)

        val exception = assertFailsWith<OAuth2AuthorizationCodeRequestAuthenticationException> {
            validator.accept(authorizationContext(audience = "other-api"))
        }

        assertEquals("invalid_target", exception.error.errorCode)
    }

    @Test
    fun tenantAuthorizationValidatorRejectsNonStringAudienceParameter() {
        val validator = TenantAuthorizationValidator(clientPolicyRepository, resourceParser, relationService, scopePolicy)

        val exception = assertFailsWith<OAuth2AuthorizationCodeRequestAuthenticationException> {
            validator.accept(authorizationContext(audience = listOf("backend-api", "other-api")))
        }

        assertEquals("invalid_target", exception.error.errorCode)
    }

    @Test
    fun tenantAuthorizationValidatorRejectsInvalidTenantResource() {
        val validator = TenantAuthorizationValidator(clientPolicyRepository, resourceParser, relationService, scopePolicy)

        val exception = assertFailsWith<OAuth2AuthorizationCodeRequestAuthenticationException> {
            validator.accept(authorizationContext(resource = "https://api.example.com/tenants/tenant-a/events/event-1"))
        }

        assertEquals("invalid_target", exception.error.errorCode)
    }

    @Test
    fun tenantAuthorizationValidatorRejectsScopeOutsideRole() {
        cacheRepository.deleteAll()
        cacheMembership(
            TenantMembership(
                tenantId = "tenant-a",
                tenantRole = RelationRole.STAFF,
                events = emptyList(),
            ),
        )
        val validator = TenantAuthorizationValidator(clientPolicyRepository, resourceParser, relationService, scopePolicy)

        val exception = assertFailsWith<OAuth2AuthorizationCodeRequestAuthenticationException> {
            validator.accept(authorizationContext(scopes = setOf("tenant.write")))
        }

        assertEquals("invalid_scope", exception.error.errorCode)
    }

    @Test
    fun jwtCustomizerAddsTenantAccessClaimsForAuthorizationCodeGrant() {
        val context = jwtContext(
            grantType = AuthorizationGrantType.AUTHORIZATION_CODE,
            scopes = setOf("tenant.read", "events.read"),
            authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("user-123")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(
                    OAuth2AuthorizationRequest::class.java.name,
                    oauthAuthorizationRequest(
                        resource = "https://api.example.com/tenants/tenant-a",
                        audience = "backend-api",
                        scopes = setOf("tenant.read", "events.read"),
                    ),
                )
                .build(),
        )

        jwtCustomizer.customize(context)

        val claims = context.claims.build().claims
        assertEquals(listOf("backend-api"), claims["aud"])
        assertEquals(TOKEN_USE_TENANT_ACCESS, claims["token_use"])
        assertEquals("tenant-a", claims["tenant_id"])
        assertEquals("https://api.example.com/tenants/tenant-a", claims["resource"])
        assertEquals("tenant.read events.read", claims["scope"])
        assertTrue(claims.containsKey("jti"))
        assertFalse(claims.containsKey("role"))
        assertFalse(claims.containsKey("tenant_role"))
        assertFalse(claims.containsKey("event_role"))
    }

    @Test
    fun jwtCustomizerRejectsTenantAccessNonStringAudienceParameter() {
        val context = jwtContext(
            grantType = AuthorizationGrantType.AUTHORIZATION_CODE,
            scopes = setOf("tenant.read"),
            authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("user-123")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(
                    OAuth2AuthorizationRequest::class.java.name,
                    oauthAuthorizationRequest(
                        resource = "https://api.example.com/tenants/tenant-a",
                        audience = listOf("backend-api", "other-api"),
                        scopes = setOf("tenant.read"),
                    ),
                )
                .build(),
        )

        val exception = assertFailsWith<OAuth2AuthenticationException> {
            jwtCustomizer.customize(context)
        }
        assertEquals("invalid_target", exception.error.errorCode)
    }

    @Test
    fun jwtCustomizerRejectsTenantAccessScopeOutsidePolicy() {
        val context = jwtContext(
            grantType = AuthorizationGrantType.AUTHORIZATION_CODE,
            scopes = setOf("admin.read"),
            authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("user-123")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(
                    OAuth2AuthorizationRequest::class.java.name,
                    oauthAuthorizationRequest(
                        resource = "https://api.example.com/tenants/tenant-a",
                        audience = "backend-api",
                        scopes = setOf("admin.read"),
                    ),
                )
                .build(),
        )

        val exception = assertFailsWith<OAuth2AuthenticationException> {
            jwtCustomizer.customize(context)
        }
        assertEquals("invalid_scope", exception.error.errorCode)
    }

    @Test
    fun jwtCustomizerRejectsTenantAccessWhenPolicyOmitsAuthorizationCodeGrant() {
        replaceClientPolicy(allowedGrantTypes = setOf(AuthorizationGrantType.TOKEN_EXCHANGE.value))
        val context = jwtContext(
            grantType = AuthorizationGrantType.AUTHORIZATION_CODE,
            scopes = setOf("tenant.read"),
            authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("user-123")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(
                    OAuth2AuthorizationRequest::class.java.name,
                    oauthAuthorizationRequest(
                        resource = "https://api.example.com/tenants/tenant-a",
                        audience = "backend-api",
                        scopes = setOf("tenant.read"),
                    ),
                )
                .build(),
        )

        val exception = assertFailsWith<OAuth2AuthenticationException> {
            jwtCustomizer.customize(context)
        }
        assertEquals("unauthorized_client", exception.error.errorCode)
    }

    @Test
    fun jwtCustomizerAddsEventAccessClaimsForTokenExchangeGrant() {
        val tokenExchange = OAuth2TokenExchangeAuthenticationToken(
            ACCESS_TOKEN_TYPE,
            "subject-token",
            ACCESS_TOKEN_TYPE,
            principal,
            null,
            null,
            setOf("https://api.example.com/tenants/tenant-a/events/event-1"),
            setOf("backend-api"),
            setOf("events.read"),
            emptyMap(),
        )
        val context = jwtContext(
            grantType = AuthorizationGrantType.TOKEN_EXCHANGE,
            scopes = setOf("events.read"),
            authorizationGrant = tokenExchange,
        )

        jwtCustomizer.customize(context)

        val claims = context.claims.build().claims
        assertEquals(listOf("backend-api"), claims["aud"])
        assertEquals(TOKEN_USE_EVENT_ACCESS, claims["token_use"])
        assertEquals("tenant-a", claims["tenant_id"])
        assertEquals("event-1", claims["event_id"])
        assertEquals("https://api.example.com/tenants/tenant-a/events/event-1", claims["resource"])
        assertEquals("events.read", claims["scope"])
        assertFalse(claims.containsKey("role"))
        assertFalse(claims.containsKey("tenant_role"))
        assertFalse(claims.containsKey("event_role"))
    }

    @Test
    fun jwtCustomizerIgnoresNonAccessTokens() {
        val context = jwtContext(
            grantType = AuthorizationGrantType.AUTHORIZATION_CODE,
            tokenType = OAuth2TokenType("id_token"),
        )

        jwtCustomizer.customize(context)

        assertFalse(context.claims.build().claims.containsKey("token_use"))
    }

    private fun replaceClientPolicy(
        allowedGrantTypes: Set<String> = setOf(
            AuthorizationGrantType.AUTHORIZATION_CODE.value,
            AuthorizationGrantType.TOKEN_EXCHANGE.value,
        ),
    ) {
        clientPolicyRepository.deleteById("client-123")
        clientPolicyRepository.save(
            ClientPolicy(
                clientId = "client-123",
                clientType = ClientType.CONFIDENTIAL,
                allowedGrantTypes = allowedGrantTypes,
                allowedTransitions = setOf(TOKEN_EXCHANGE_TRANSITION_TENANT_TO_EVENT),
                allowedAudiences = setOf("backend-api"),
                allowedScopes = setOf("tenant.read", "tenant.write", "events.read", "events.write"),
                tenantAccessTtl = Duration.ofSeconds(900),
                eventAccessTtl = Duration.ofSeconds(600),
            ),
        )
    }

    private fun authorizationRequest(): MockHttpServletRequest =
        MockHttpServletRequest("GET", "/oauth2/authorize").apply {
            setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "code")
            setParameter(OAuth2ParameterNames.CLIENT_ID, "client-123")
            setParameter(OAuth2ParameterNames.REDIRECT_URI, "http://127.0.0.1:8080/login/oauth2/code/client-123")
            setParameter(OAuth2ParameterNames.SCOPE, "tenant.read")
            setParameter(OAuth2ParameterNames.STATE, "state-1")
            queryString = listOf(
                "${OAuth2ParameterNames.RESPONSE_TYPE}=code",
                "${OAuth2ParameterNames.CLIENT_ID}=client-123",
                "${OAuth2ParameterNames.REDIRECT_URI}=http%3A%2F%2F127.0.0.1%3A8080%2Flogin%2Foauth2%2Fcode%2Fclient-123",
                "${OAuth2ParameterNames.SCOPE}=tenant.read",
                "${OAuth2ParameterNames.STATE}=state-1",
            ).joinToString("&")
        }

    private fun cacheMembership(membership: TenantMembership) {
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId(membership.tenantId, "user-123"),
                membership = membership,
                cachedAt = Instant.EPOCH,
                expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        )
    }

    private fun authorizationContext(
        resource: String = "https://api.example.com/tenants/tenant-a",
        audience: Any = "backend-api",
        scopes: Set<String> = setOf("tenant.read"),
    ): OAuth2AuthorizationCodeRequestAuthenticationContext {
        val authentication = OAuth2AuthorizationCodeRequestAuthenticationToken(
            "http://localhost:8080/oauth2/authorize",
            "client-123",
            principal,
            "http://127.0.0.1:8080/login/oauth2/code/client-123",
            "state-1",
            scopes,
            mapOf(
                OAuth2ParameterNames.RESOURCE to resource,
                OAuth2ParameterNames.AUDIENCE to audience,
            ),
        )
        return OAuth2AuthorizationCodeRequestAuthenticationContext.with(authentication)
            .registeredClient(registeredClient)
            .authorizationRequest(oauthAuthorizationRequest(resource, audience, scopes))
            .build()
    }

    private fun oauthAuthorizationRequest(
        resource: String,
        audience: Any,
        scopes: Set<String>,
    ): OAuth2AuthorizationRequest =
        OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("http://localhost:8080/oauth2/authorize")
            .clientId("client-123")
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-123")
            .state("state-1")
            .scopes(scopes)
            .additionalParameters(
                mapOf(
                    OAuth2ParameterNames.RESOURCE to resource,
                    OAuth2ParameterNames.AUDIENCE to audience,
                ),
            )
            .build()

    private fun jwtContext(
        grantType: AuthorizationGrantType,
        scopes: Set<String> = setOf("tenant.read"),
        tokenType: OAuth2TokenType = OAuth2TokenType.ACCESS_TOKEN,
        authorization: OAuth2Authorization? = null,
        authorizationGrant: org.springframework.security.core.Authentication = principal,
    ): JwtEncodingContext {
        val builder = JwtEncodingContext.with(
            JwsHeader.with(SignatureAlgorithm.RS256),
            JwtClaimsSet.builder().issuer("http://localhost:8080").subject("user-123"),
        )
            .registeredClient(registeredClient)
            .principal(principal)
            .authorizedScopes(scopes)
            .tokenType(tokenType)
            .authorizationGrantType(grantType)
            .authorizationGrant(authorizationGrant)
        if (authorization != null) {
            builder.authorization(authorization)
        }
        return builder.build()
    }
}
