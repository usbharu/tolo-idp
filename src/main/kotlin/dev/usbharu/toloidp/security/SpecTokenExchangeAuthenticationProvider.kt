package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopeNotAllowedException
import dev.usbharu.toloidp.scope.ScopePolicy
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator

class SpecTokenExchangeAuthenticationProvider(
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>,
    private val clientPolicyRepository: ClientPolicyRepository,
    private val resourceParser: ResourceParser,
    private val relationService: RelationService,
    private val scopePolicy: ScopePolicy,
    private val jdbcClient: JdbcClient,
    private val auditService: AuditService,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val tokenExchange = authentication as OAuth2TokenExchangeAuthenticationToken
        val clientPrincipal = authenticatedClient(tokenExchange)
        val registeredClient = clientPrincipal.registeredClient
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_client"))
        val requestedScopes = tokenExchange.scopes
        var audit = TokenAuditEvent(
            clientId = registeredClient.clientId,
            requestedTokenUse = TOKEN_USE_EVENT_ACCESS,
            requestedAudience = tokenExchange.audiences.singleOrNull(),
            requestedResource = tokenExchange.resources.singleOrNull(),
            requestedScope = requestedScopes.toList(),
            result = "failure",
        )

        try {
            val policy = clientPolicyRepository.findByClientId(registeredClient.clientId)
                ?: fail("invalid_request", "client_not_allowed")
            if (policy.clientType != ClientType.CONFIDENTIAL) {
                fail("invalid_grant", "client_not_allowed")
            }
            if (AuthorizationGrantType.TOKEN_EXCHANGE.value !in policy.allowedGrantTypes ||
                TOKEN_EXCHANGE_TRANSITION_TENANT_TO_EVENT !in policy.allowedTransitions
            ) {
                fail("invalid_grant", "invalid_token_use_transition")
            }
            if (tokenExchange.subjectTokenType != ACCESS_TOKEN_TYPE && tokenExchange.subjectTokenType != JWT_TOKEN_TYPE) {
                fail("invalid_request", "subject_token_type")
            }
            val audience = tokenExchange.audiences.singleOrNull()
                ?: fail("invalid_target", "audience_not_allowed")
            if (audience !in policy.allowedAudiences) {
                fail("invalid_target", "audience_not_allowed")
            }
            val eventResource = try {
                resourceParser.parseEvent(tokenExchange.resources.singleOrNull() ?: fail("invalid_target", "resource_invalid_format"))
            } catch (ex: RuntimeException) {
                fail("invalid_target", "resource_invalid_format")
            }

            val subjectAuthorization = authorizationService.findByToken(tokenExchange.subjectToken, OAuth2TokenType.ACCESS_TOKEN)
                ?: fail("invalid_grant", "token_revoked")
            val subjectToken = subjectAuthorization.getToken<OAuth2Token>(tokenExchange.subjectToken)
                ?: fail("invalid_grant", "token_revoked")
            val claims = subjectToken.claims ?: fail("invalid_grant", "token_revoked")
            if (!subjectToken.isActive || isDenied(claims["jti"] as? String)) {
                fail("invalid_grant", "token_revoked")
            }
            val subject = claims["sub"] as? String ?: subjectAuthorization.principalName
            audit = audit.copy(
                subject = subject,
                sourceTokenUse = claims["token_use"] as? String,
                tenantId = eventResource.tenantId,
                eventId = eventResource.eventId,
            )
            if (claims["token_use"] != TOKEN_USE_TENANT_ACCESS) {
                fail("invalid_grant", "invalid_token_use_transition")
            }
            if (claims["tenant_id"] != eventResource.tenantId) {
                fail("invalid_grant", "event_not_in_tenant")
            }
            val subjectScopes = splitScope(claims["scope"])
            try {
                scopePolicy.requireAllowed(requestedScopes, policy.allowedScopes, "scope_not_allowed_for_client")
                scopePolicy.requireAllowed(requestedScopes, subjectScopes, "scope_exceeds_subject_token")
                val membership = relationService.getMembership(eventResource.tenantId, subject)
                val eventMembership = membership.events.find { it.eventId == eventResource.eventId }
                    ?: fail("invalid_grant", "user_not_event_member")
                scopePolicy.requireAllowed(requestedScopes, scopePolicy.allowedScopes(eventMembership.role), "scope_not_allowed_for_role")
            } catch (ex: ScopeNotAllowedException) {
                val code = if (ex.reason == "scope_exceeds_subject_token") "invalid_grant" else "invalid_scope"
                fail(code, ex.reason)
            } catch (ex: RelationLookupException) {
                fail("invalid_grant", ex.reason)
            }

            val principal = subjectAuthorization.getAttribute<Authentication>(java.security.Principal::class.java.name)
                ?: fail("invalid_grant", "token_revoked")
            val tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorization(subjectAuthorization)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(requestedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrant(tokenExchange)
                .build()
            val generatedAccessToken = tokenGenerator.generate(tokenContext)
                ?: fail("server_error", "token_generation_failed")
            val accessToken = toAccessToken(registeredClient, generatedAccessToken, requestedScopes)

            val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(subjectAuthorization.principalName)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizedScopes(requestedScopes)
                .attribute(java.security.Principal::class.java.name, principal)
            authorizationBuilder.token(accessToken) {
                if (generatedAccessToken is Jwt) {
                    it[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = generatedAccessToken.claims
                }
                it[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = false
                it[OAuth2TokenFormat::class.java.name] = OAuth2TokenFormat.SELF_CONTAINED.value
            }
            authorizationService.save(authorizationBuilder.build())
            auditService.record(
                audit.copy(
                    issuedScope = requestedScopes.toList(),
                    result = "success",
                    failureReason = null,
                    issuedJti = (generatedAccessToken as? Jwt)?.id,
                ),
            )
            return OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                null,
                mapOf(OAuth2ParameterNames.ISSUED_TOKEN_TYPE to ACCESS_TOKEN_TYPE),
            )
        } catch (ex: SpecOAuth2Failure) {
            auditService.record(audit.copy(result = "failure", failureReason = ex.failureReason))
            throw OAuth2AuthenticationException(OAuth2Error(ex.errorCode))
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2TokenExchangeAuthenticationToken::class.java.isAssignableFrom(authentication)

    private fun authenticatedClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
        val principal = authentication.principal
        if (principal is OAuth2ClientAuthenticationToken && principal.isAuthenticated) {
            return principal
        }
        throw OAuth2AuthenticationException(OAuth2Error("invalid_client"))
    }

    private fun toAccessToken(
        registeredClient: RegisteredClient,
        token: OAuth2Token,
        scopes: Set<String>,
    ): OAuth2AccessToken =
        OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            token.tokenValue,
            token.issuedAt,
            token.expiresAt,
            scopes,
        )

    private fun isDenied(jti: String?): Boolean {
        if (jti == null) {
            return false
        }
        return jdbcClient.sql("select count(*) from idp_jti_denylist where jti = :jti and expires_at > current_timestamp")
            .param("jti", jti)
            .query(Int::class.java)
            .single() > 0
    }

    private fun splitScope(value: Any?): Set<String> =
        when (value) {
            is String -> value.split(' ').filter { it.isNotEmpty() }.toSet()
            is Collection<*> -> value.filterIsInstance<String>().toSet()
            else -> emptySet()
        }

    private fun fail(errorCode: String, reason: String): Nothing {
        throw SpecOAuth2Failure(errorCode, reason)
    }
}

private class SpecOAuth2Failure(
    val errorCode: String,
    val failureReason: String,
) : RuntimeException(failureReason)
