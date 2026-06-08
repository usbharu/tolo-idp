package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopeNotAllowedException
import dev.usbharu.toloidp.scope.ScopePolicy
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator
import java.util.function.Consumer

class TenantAuthorizationValidator(
    private val clientPolicyRepository: ClientPolicyRepository,
    private val resourceParser: ResourceParser,
    private val relationService: RelationService,
    private val scopePolicy: ScopePolicy,
) : Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {
    private val defaultValidator = OAuth2AuthorizationCodeRequestAuthenticationValidator()

    override fun accept(context: OAuth2AuthorizationCodeRequestAuthenticationContext) {
        log.trace("accept started: clientId={}", context.registeredClient.clientId)
        defaultValidator.accept(context)
        val authentication = context.getAuthentication<OAuth2AuthorizationCodeRequestAuthenticationToken>()
        val clientId = context.registeredClient.clientId
        val policy = clientPolicyRepository.findByClientId(clientId)
            ?: throwAuthorizationError(OAuth2ErrorCodes.INVALID_REQUEST, "client_id")
        log.debug(
            "Authorization request client policy loaded: clientId={}, allowedAudienceCount={}, allowedScopeCount={}",
            clientId,
            policy.allowedAudiences.size,
            policy.allowedScopes.size,
        )

        val resource = authentication.additionalParameters[OAuth2ParameterNames.RESOURCE] as? String
            ?: throwAuthorizationError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESOURCE)
        val tenantResource = try {
            resourceParser.parseTenant(resource)
        } catch (ex: RuntimeException) {
            log.warn("Authorization request rejected invalid tenant resource: clientId={}", clientId, ex)
            throwAuthorizationError("invalid_target", OAuth2ParameterNames.RESOURCE)
        }

        val audience = authentication.additionalParameters[OAuth2ParameterNames.AUDIENCE] as? String
            ?: policy.allowedAudiences.singleOrNull()
            ?: throwAuthorizationError("invalid_target", OAuth2ParameterNames.AUDIENCE)
        if (audience !in policy.allowedAudiences) {
            throwAuthorizationError("invalid_target", OAuth2ParameterNames.AUDIENCE)
        }

        val requestedScopes = authentication.scopes.orEmpty()
        try {
            scopePolicy.requireAllowed(requestedScopes, policy.allowedScopes, "scope_not_allowed_for_client")
            val membership = relationService.getMembership(tenantResource.tenantId, (authentication.principal as org.springframework.security.core.Authentication).name)
            log.debug(
                "Authorization request membership loaded: clientId={}, tenantId={}, principal={}, tenantRole={}, scopeCount={}",
                clientId,
                tenantResource.tenantId,
                (authentication.principal as org.springframework.security.core.Authentication).name,
                membership.tenantRole,
                requestedScopes.size,
            )
            scopePolicy.requireAllowed(requestedScopes, scopePolicy.allowedScopes(membership.tenantRole), "scope_not_allowed_for_role")
        } catch (ex: ScopeNotAllowedException) {
            log.warn(
                "Authorization request scope validation failed: clientId={}, tenantId={}, scopeCount={}",
                clientId,
                tenantResource.tenantId,
                requestedScopes.size,
                ex,
            )
            throwAuthorizationError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE)
        } catch (ex: RelationLookupException) {
            log.warn("Authorization request relation lookup failed: clientId={}, tenantId={}", clientId, tenantResource.tenantId, ex)
            throwAuthorizationError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.RESOURCE)
        }
        log.debug(
            "Authorization request validation completed: clientId={}, tenantId={}, audience={}, scopeCount={}",
            clientId,
            tenantResource.tenantId,
            audience,
            requestedScopes.size,
        )
        log.trace("accept completed: clientId={}, tenantId={}", clientId, tenantResource.tenantId)
    }

    private fun throwAuthorizationError(errorCode: String, parameter: String): Nothing {
        val error = OAuth2Error(errorCode, "OAuth 2.0 Parameter: $parameter", null)
        throw OAuth2AuthorizationCodeRequestAuthenticationException(error, null)
    }

    companion object {
        private val log = LoggerFactory.getLogger(TenantAuthorizationValidator::class.java)
    }
}
