package dev.usbharu.toloidp.ratelimit

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.MediaType
import org.springframework.security.core.context.SecurityContextHolder
import tools.jackson.databind.ObjectMapper

class RateLimitIdentityExtractor(
    private val objectMapper: ObjectMapper,
) {
    fun identity(request: HttpServletRequest): RateLimitIdentity =
        RateLimitIdentity(
            ip = request.remoteAddr,
            userId = authenticatedUserId() ?: loginUserId(request),
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
}
