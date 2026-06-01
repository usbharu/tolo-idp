package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopeNotAllowedException
import dev.usbharu.toloidp.scope.ScopePolicy
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.UUID

@Component
class ToloJwtCustomizer(
    private val clientPolicyRepository: ClientPolicyRepository,
    private val resourceParser: ResourceParser,
    private val relationService: RelationService,
    private val scopePolicy: ScopePolicy,
) : OAuth2TokenCustomizer<JwtEncodingContext> {
    override fun customize(context: JwtEncodingContext) {
        if (context.tokenType != OAuth2TokenType.ACCESS_TOKEN) {
            return
        }
        when (context.authorizationGrantType) {
            AuthorizationGrantType.AUTHORIZATION_CODE -> customizeTenantAccess(context)
            AuthorizationGrantType.TOKEN_EXCHANGE -> customizeEventAccess(context)
        }
    }

    private fun customizeTenantAccess(context: JwtEncodingContext) {
        val clientId = context.registeredClient.clientId
        val policy = clientPolicyRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException("invalid_request")
        val authorizationRequest = context.authorization
            ?.getAttribute<OAuth2AuthorizationRequest>(OAuth2AuthorizationRequest::class.java.name)
            ?: throw OAuth2AuthenticationException("invalid_grant")
        val resource = authorizationRequest.additionalParameters[OAuth2ParameterNames.RESOURCE] as? String
            ?: throw OAuth2AuthenticationException("invalid_grant")
        val tenantResource = try {
            resourceParser.parseTenant(resource)
        } catch (ex: RuntimeException) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        }
        val audience = authorizationRequest.additionalParameters[OAuth2ParameterNames.AUDIENCE] as? String
            ?: policy.allowedAudiences.singleOrNull()
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        if (audience !in policy.allowedAudiences) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        }

        try {
            val principal = context.getPrincipal<org.springframework.security.core.Authentication>()
            val membership = relationService.getMembership(tenantResource.tenantId, principal.name)
            scopePolicy.requireAllowed(context.authorizedScopes, policy.allowedScopes, "scope_not_allowed_for_client")
            scopePolicy.requireAllowed(context.authorizedScopes, scopePolicy.allowedScopes(membership.tenantRole), "scope_not_allowed_for_role")
        } catch (ex: ScopeNotAllowedException) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_scope"))
        } catch (ex: RelationLookupException) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_grant"))
        }

        val now = Instant.now()
        context.claims
            .audience(listOf(audience))
            .issuedAt(now)
            .notBefore(now)
            .expiresAt(now.plus(policy.tenantAccessTtl))
            .id(UUID.randomUUID().toString())
            .claim("client_id", clientId)
            .claim("scope", context.authorizedScopes.joinToString(" "))
            .claim("token_use", TOKEN_USE_TENANT_ACCESS)
            .claim("resource", tenantResource.value)
            .claim("tenant_id", tenantResource.tenantId)
    }

    private fun customizeEventAccess(context: JwtEncodingContext) {
        val tokenExchange = context.getAuthorizationGrant<OAuth2TokenExchangeAuthenticationToken>()
        val policy = clientPolicyRepository.findByClientId(context.registeredClient.clientId)
            ?: throw OAuth2AuthenticationException("invalid_request")
        val resource = tokenExchange.resources.singleOrNull()
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        val eventResource = try {
            resourceParser.parseEvent(resource)
        } catch (ex: RuntimeException) {
            throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        }
        val audience = tokenExchange.audiences.singleOrNull()
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))

        val now = Instant.now()
        context.claims
            .audience(listOf(audience))
            .issuedAt(now)
            .notBefore(now)
            .expiresAt(now.plus(policy.eventAccessTtl))
            .id(UUID.randomUUID().toString())
            .claim("client_id", context.registeredClient.clientId)
            .claim("scope", context.authorizedScopes.joinToString(" "))
            .claim("token_use", TOKEN_USE_EVENT_ACCESS)
            .claim("resource", eventResource.value)
            .claim("tenant_id", eventResource.tenantId)
            .claim("event_id", eventResource.eventId)
    }
}
