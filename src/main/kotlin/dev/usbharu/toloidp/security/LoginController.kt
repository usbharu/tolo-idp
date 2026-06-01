package dev.usbharu.toloidp.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.servlet.http.HttpSession
import dev.usbharu.toloidp.relation.RelationLookupException
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.tenant.SELECTED_TENANT_SESSION_ATTRIBUTE
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
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
        resourceParser.requireValidId(request.tenantId)
        val user = try {
            userDetailsService.loadUserByUsername(request.username)
        } catch (ex: RuntimeException) {
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials")
        }
        if (!passwordEncoder.matches(request.password, user.password)) {
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials")
        }
        try {
            relationService.getMembership(request.tenantId, user.username)
        } catch (ex: RelationLookupException) {
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
        SecurityContextHolder.clearContext()
        session?.invalidate()
        response.status = HttpStatus.NO_CONTENT.value()
        return ResponseEntity.noContent().build()
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
