package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopeNotAllowedException
import dev.usbharu.toloidp.scope.ScopePolicy
import org.slf4j.LoggerFactory
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
        log.trace("customizeTenantAccess started: clientId={}, scopeCount={}", clientId, context.authorizedScopes.size)
        val policy = clientPolicyRepository.findByClientId(clientId)
            ?: throw OAuth2AuthenticationException("invalid_request")
        log.debug(
            "Tenant access client policy loaded: clientId={}, allowedAudienceCount={}, allowedScopeCount={}",
            clientId,
            policy.allowedAudiences.size,
            policy.allowedScopes.size,
        )
        val authorizationRequest = context.authorization
            ?.getAttribute<OAuth2AuthorizationRequest>(OAuth2AuthorizationRequest::class.java.name)
            ?: throw OAuth2AuthenticationException("invalid_grant")
        val resource = authorizationRequest.additionalParameters[OAuth2ParameterNames.RESOURCE] as? String
            ?: throw OAuth2AuthenticationException("invalid_grant")
        val tenantResource = try {
            resourceParser.parseTenant(resource)
        } catch (ex: RuntimeException) {
            log.warn("Tenant access JWT customization rejected invalid resource: clientId={}", clientId, ex)
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
            log.debug(
                "Tenant access membership loaded: clientId={}, tenantId={}, principal={}, tenantRole={}",
                clientId,
                tenantResource.tenantId,
                principal.name,
                membership.tenantRole,
            )
            scopePolicy.requireAllowed(context.authorizedScopes, policy.allowedScopes, "scope_not_allowed_for_client")
            scopePolicy.requireAllowed(context.authorizedScopes, scopePolicy.allowedScopes(membership.tenantRole), "scope_not_allowed_for_role")
        } catch (ex: ScopeNotAllowedException) {
            log.warn(
                "Tenant access scope validation failed: clientId={}, tenantId={}, scopeCount={}",
                clientId,
                tenantResource.tenantId,
                context.authorizedScopes.size,
                ex,
            )
            throw OAuth2AuthenticationException(OAuth2Error("invalid_scope"))
        } catch (ex: RelationLookupException) {
            log.warn("Tenant access relation lookup failed: clientId={}, tenantId={}", clientId, tenantResource.tenantId, ex)
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
        log.debug(
            "Tenant access JWT claims customized: clientId={}, tenantId={}, audience={}, scopeCount={}",
            clientId,
            tenantResource.tenantId,
            audience,
            context.authorizedScopes.size,
        )
        log.trace("customizeTenantAccess completed: clientId={}, tenantId={}", clientId, tenantResource.tenantId)
    }

    private fun customizeEventAccess(context: JwtEncodingContext) {
        log.trace(
            "customizeEventAccess started: clientId={}, scopeCount={}",
            context.registeredClient.clientId,
            context.authorizedScopes.size,
        )
        val tokenExchange = context.getAuthorizationGrant<OAuth2TokenExchangeAuthenticationToken>()
        val policy = clientPolicyRepository.findByClientId(context.registeredClient.clientId)
            ?: throw OAuth2AuthenticationException("invalid_request")
        val resource = tokenExchange.resources.singleOrNull()
            ?: throw OAuth2AuthenticationException(OAuth2Error("invalid_target"))
        val eventResource = try {
            resourceParser.parseEvent(resource)
        } catch (ex: RuntimeException) {
            log.warn("Event access JWT customization rejected invalid resource: clientId={}", context.registeredClient.clientId, ex)
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
        log.debug(
            "Event access JWT claims customized: clientId={}, tenantId={}, eventId={}, audience={}, scopeCount={}",
            context.registeredClient.clientId,
            eventResource.tenantId,
            eventResource.eventId,
            audience,
            context.authorizedScopes.size,
        )
        log.trace(
            "customizeEventAccess completed: clientId={}, tenantId={}, eventId={}",
            context.registeredClient.clientId,
            eventResource.tenantId,
            eventResource.eventId,
        )
    }

    companion object {
        private val log = LoggerFactory.getLogger(ToloJwtCustomizer::class.java)
    }
}
