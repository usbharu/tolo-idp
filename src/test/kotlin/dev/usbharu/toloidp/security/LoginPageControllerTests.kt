package dev.usbharu.toloidp.security

import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.web.savedrequest.SimpleSavedRequest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest
@AutoConfigureMockMvc
class LoginPageControllerTests(
    @Autowired private val mockMvc: MockMvc,
) {
    @Test
    fun loginPageIsPubliclyAvailable() {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
            .andExpect(content().string(containsString("id=\"login-form\"")))
            .andExpect(content().string(not(containsString("data-continue-url"))))
    }

    @Test
    fun htmlAuthorizationRequestRedirectsToLoginAndIsRenderedAsContinuation() {
        val result = mockMvc.perform(
            get("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", "client-123")
                .queryParam("redirect_uri", "http://127.0.0.1:8080/login/oauth2/code/client-123")
                .queryParam("scope", "tenant.read")
                .queryParam("state", "state-1")
                .queryParam("resource", "https://api.example.com/tenants/tenant-a")
                .queryParam("audience", "backend-api")
                .accept(MediaType.TEXT_HTML),
        )
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("/login"))
            .andReturn()

        mockMvc.perform(get("/login").session(result.request.session as MockHttpSession))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("data-continue-url=\"/oauth2/authorize?")))
            .andExpect(content().string(containsString("client_id=client-123")))
    }

    @Test
    fun loginPageRejectsExternalAndUnrelatedSavedRequests() {
        val externalSession = savedRequestSession("https://evil.example/oauth2/authorize?client_id=attacker")
        mockMvc.perform(get("/login").session(externalSession))
            .andExpect(status().isOk)
            .andExpect(content().string(not(containsString("data-continue-url"))))

        val unrelatedSession = savedRequestSession("http://localhost/private")
        mockMvc.perform(get("/login").session(unrelatedSession))
            .andExpect(status().isOk)
            .andExpect(content().string(not(containsString("data-continue-url"))))
    }

    @Test
    fun loginPageIgnoresMalformedSavedRequest() {
        mockMvc.perform(get("/login").session(savedRequestSession("https://[invalid")))
            .andExpect(status().isOk)
            .andExpect(content().string(not(containsString("data-continue-url"))))
    }

    @Test
    fun nonHtmlTokenRequestIsNotRedirectedToLogin() {
        mockMvc.perform(
            post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON),
        )
            .andExpect(status().isUnauthorized)
            .andExpect(header().doesNotExist(HttpHeaders.LOCATION))
    }

    private fun savedRequestSession(redirectUrl: String): MockHttpSession =
        MockHttpSession().apply {
            setAttribute("SPRING_SECURITY_SAVED_REQUEST", SimpleSavedRequest(redirectUrl))
        }
}
