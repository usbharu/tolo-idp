package dev.usbharu.toloidp.security

import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.mock.web.MockHttpSession
import java.time.Instant
import kotlin.test.assertTrue

@SpringBootTest
@AutoConfigureMockMvc
class LoginControllerTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
) {
    @BeforeEach
    fun setUp() {
        cacheRepository.deleteAll()
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId("tenant-a", "user-123"),
                membership = TenantMembership(
                    tenantId = "tenant-a",
                    tenantRole = RelationRole.OWNER,
                    events = listOf(EventMembership("event-1", RelationRole.STAFF)),
                ),
                cachedAt = Instant.EPOCH,
                expiresAt = Instant.parse("2030-01-01T00:00:00Z"),
            ),
        )
    }

    @Test
    fun loginCreatesSessionAndReturnsSelectedTenantResource() {
        mockMvc.perform(loginRequest("user-123", "password", "tenant-a"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.username").value("user-123"))
            .andExpect(jsonPath("$.tenantId").value("tenant-a"))
            .andExpect(jsonPath("$.resource").value("https://api.example.com/tenants/tenant-a"))
            .andExpect(jsonPath("$.authorities[0]").value("ROLE_USER"))
            .andExpect(content().string(not(containsString("password"))))
    }

    @Test
    fun loginInvalidatesExistingSessionBeforeAuthentication() {
        val preAuthSession = MockHttpSession()

        mockMvc.perform(loginRequest("user-123", "password", "tenant-a").session(preAuthSession))
            .andExpect(status().isOk)

        assertTrue(preAuthSession.isInvalid)
    }

    @Test
    fun loginRejectsBadCredentials() {
        mockMvc.perform(loginRequest("user-123", "wrong-password", "tenant-a"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun loginRejectsUnknownUser() {
        mockMvc.perform(loginRequest("missing-user", "password", "tenant-a"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun loginRejectsTenantWithoutMembership() {
        mockMvc.perform(loginRequest("user-123", "password", "tenant-missing"))
            .andExpect(status().isForbidden)
    }

    @Test
    fun loginRejectsInvalidTenantIdWithoutTrimming() {
        mockMvc.perform(loginRequest("user-123", "password", " tenant-a"))
            .andExpect(status().isBadRequest)
    }

    @Test
    fun logoutInvalidatesExistingSession() {
        val session = mockMvc.perform(loginRequest("user-123", "password", "tenant-a"))
            .andExpect(status().isOk)
            .andReturn()
            .request
            .session as MockHttpSession

        mockMvc.perform(post("/api/logout").session(session))
            .andExpect(status().isNoContent)
    }

    private fun loginRequest(username: String, password: String, tenantId: String) =
        post("/api/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                """
                {
                  "username": "$username",
                  "password": "$password",
                  "tenantId": "$tenantId"
                }
                """.trimIndent(),
            )
}
