package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.MediaType
import org.springframework.security.core.context.SecurityContextHolder
import tools.jackson.databind.ObjectMapper
import java.nio.charset.StandardCharsets
import java.util.Base64

class RateLimitIdentityExtractor(
    private val objectMapper: ObjectMapper,
) {
    fun identity(request: HttpServletRequest): RateLimitIdentity =
        RateLimitIdentity(
            ip = request.remoteAddr,
            userId = authenticatedUserId() ?: loginUserId(request) ?: tokenExchangeSubject(request),
        )

    private fun authenticatedUserId(): String? {
        val authentication = SecurityContextHolder.getContext().authentication ?: return null
        if (!authentication.isAuthenticated || authentication.name.isNullOrBlank()) {
            return null
        }
        return authentication.name
    }

    private fun loginUserId(request: HttpServletRequest): String? {
        if (request.method != "POST" || request.requestURI != "/api/login") {
            return null
        }
        if (!request.contentType.orEmpty().startsWith(MediaType.APPLICATION_JSON_VALUE)) {
            return null
        }
        val cached = request as? CachedBodyHttpServletRequest ?: return null
        val body = cached.cachedBody()
        if (body.isEmpty()) {
            return null
        }
        return try {
            objectMapper.readTree(body)["username"]?.stringValue()?.takeIf { it.isNotBlank() }
        } catch (_: RuntimeException) {
            null
        }
    }

    private fun tokenExchangeSubject(request: HttpServletRequest): String? {
        if (request.method != "POST" || request.requestURI != "/oauth2/token") {
            return null
        }
        if (request.getParameter("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange") {
            return null
        }
        val subjectToken = request.getParameter("subject_token")?.takeIf { it.isNotBlank() } ?: return null
        return jwtSubjectWithoutValidation(subjectToken)
    }

    private fun jwtSubjectWithoutValidation(token: String): String? {
        val parts = token.split(".")
        if (parts.size < 2) {
            return null
        }
        return try {
            val claimsJson = String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
            objectMapper.readTree(claimsJson)["sub"]?.stringValue()?.takeIf { it.isNotBlank() }
        } catch (_: RuntimeException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}
