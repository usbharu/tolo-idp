package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationConverter

class TenantAwareAuthorizationRequestConverter(
    private val resourceParser: ResourceParser,
) : AuthenticationConverter {
    private val delegate = OAuth2AuthorizationCodeRequestAuthenticationConverter()

    override fun convert(request: HttpServletRequest): Authentication? {
        val converted = delegate.convert(request)
        if (converted !is OAuth2AuthorizationCodeRequestAuthenticationToken) {
            return converted
        }

        val tenantId = request.getSession(false)?.getAttribute(SELECTED_TENANT_SESSION_ATTRIBUTE) as? String
            ?: return converted
        val additionalParameters = converted.additionalParameters.toMutableMap()
        additionalParameters[OAuth2ParameterNames.RESOURCE] = resourceParser.tenantResource(tenantId)
        return OAuth2AuthorizationCodeRequestAuthenticationToken(
            converted.authorizationUri,
            converted.clientId,
            converted.principal as Authentication,
            converted.redirectUri,
            converted.state,
            converted.scopes,
            additionalParameters,
        )
    }
}
