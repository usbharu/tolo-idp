package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import java.net.URI

@Controller
class LoginPageController {
    private val requestCache = HttpSessionRequestCache()

    @GetMapping("/login")
    fun loginPage(
        request: HttpServletRequest,
        response: HttpServletResponse,
        model: Model,
    ): String {
        val savedRequest = requestCache.getRequest(request, response)
        model.addAttribute("continueUrl", safeAuthorizationContinuation(savedRequest?.redirectUrl, request))
        return "login"
    }

    private fun safeAuthorizationContinuation(redirectUrl: String?, request: HttpServletRequest): String? {
        if (redirectUrl == null) {
            return null
        }
        val uri = try {
            URI.create(redirectUrl)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (uri.path != "/oauth2/authorize" || !isSameOrigin(uri, request)) {
            return null
        }
        return buildString {
            append(uri.rawPath)
            uri.rawQuery?.let {
                append('?')
                append(it)
            }
        }
    }

    private fun isSameOrigin(uri: URI, request: HttpServletRequest): Boolean {
        if (!uri.isAbsolute) {
            return true
        }
        return uri.scheme.equals(request.scheme, ignoreCase = true) &&
            uri.host.equals(request.serverName, ignoreCase = true) &&
            effectivePort(uri.scheme, uri.port) == effectivePort(request.scheme, request.serverPort)
    }

    private fun effectivePort(scheme: String, port: Int): Int =
        when {
            port >= 0 -> port
            scheme.equals("https", ignoreCase = true) -> 443
            else -> 80
        }
}
