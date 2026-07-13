package dev.usbharu.toloidp.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import org.springframework.web.filter.OncePerRequestFilter

class AuthorizationLoginRedirectFilter : OncePerRequestFilter() {
    private val htmlRequestMatcher = MediaTypeRequestMatcher(MediaType.TEXT_HTML)
    private val requestCache = HttpSessionRequestCache()
    private val loginEntryPoint = LoginUrlAuthenticationEntryPoint("/login")

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val authentication = SecurityContextHolder.getContext().authentication
        val needsLogin = request.method == "GET" &&
            request.requestURI == "/oauth2/authorize" &&
            htmlRequestMatcher.matches(request) &&
            (authentication == null || !authentication.isAuthenticated)

        if (!needsLogin) {
            filterChain.doFilter(request, response)
            return
        }

        requestCache.saveRequest(request, response)
        loginEntryPoint.commence(
            request,
            response,
            InsufficientAuthenticationException("Authentication is required for authorization"),
        )
    }
}
