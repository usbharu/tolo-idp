package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.servlet.http.HttpSession
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.resource.ResourceValidationException
import dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException

@RestController
@RequestMapping("/api")
class LoginController(
    private val userDetailsService: UserDetailsService,
    private val passwordEncoder: PasswordEncoder,
    private val relationService: RelationService,
    private val resourceParser: ResourceParser,
) {
    @PostMapping("/login")
    fun login(
        @RequestBody request: LoginRequest,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Any> {
        log.info("Login started: username={}, tenantId={}", request.username, request.tenantId)
        try {
            resourceParser.requireValidId(request.tenantId)
        } catch (ex: ResourceValidationException) {
            log.warn("Login rejected due to invalid tenant id: username={}, tenantId={}", request.username, request.tenantId, ex)
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid tenantId")
        }
        val user = try {
            userDetailsService.loadUserByUsername(request.username)
        } catch (ex: RuntimeException) {
            log.warn("Login rejected due to user lookup failure: username={}, tenantId={}", request.username, request.tenantId, ex)
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials")
        }
        if (!passwordEncoder.matches(request.password, user.password)) {
            log.warn("Login rejected due to bad credentials: username={}, tenantId={}", request.username, request.tenantId)
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials")
        }
        try {
            relationService.getMembership(request.tenantId, user.username)
        } catch (ex: RelationLookupException) {
            log.warn("Login rejected due to tenant membership failure: username={}, tenantId={}", user.username, request.tenantId, ex)
            throw ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant is not allowed")
        }
        val authentication = UsernamePasswordAuthenticationToken.authenticated(
            user.username,
            null,
            user.authorities,
        )
        val context = SecurityContextImpl(authentication)
        SecurityContextHolder.setContext(context)
        val session = httpRequest.getSession(true)
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context)
        session.setAttribute(SELECTED_TENANT_SESSION_ATTRIBUTE, request.tenantId)
        log.info("Login completed: username={}, tenantId={}, authorityCount={}", user.username, request.tenantId, user.authorities.size)
        return ResponseEntity.ok(
            LoginResponse(
                username = user.username,
                tenantId = request.tenantId,
                resource = resourceParser.tenantResource(request.tenantId),
                authorities = user.authorities.mapNotNull { it.authority },
            ),
        )
    }

    @PostMapping("/logout")
    fun logout(
        session: HttpSession?,
        response: HttpServletResponse,
    ): ResponseEntity<Void> {
        log.info("Logout started: sessionPresent={}", session != null)
        SecurityContextHolder.clearContext()
        session?.invalidate()
        response.status = HttpStatus.NO_CONTENT.value()
        log.info("Logout completed: sessionInvalidated={}", session != null)
        return ResponseEntity.noContent().build()
    }

    companion object {
        private val log = LoggerFactory.getLogger(LoginController::class.java)
    }
}

data class LoginRequest(
    val username: String,
    val password: String,
    val tenantId: String,
)

data class LoginResponse(
    val username: String,
    val tenantId: String,
    val resource: String,
    val authorities: List<String>,
)
