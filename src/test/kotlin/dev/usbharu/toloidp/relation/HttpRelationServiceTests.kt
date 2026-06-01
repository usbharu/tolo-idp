package dev.usbharu.toloidp.relation

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HttpRelationServiceTests {
    private lateinit var server: HttpServer
    private lateinit var service: HttpRelationService
    private val parser = ResourceParser(IdpProperties())

    @BeforeEach
    fun setUp() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.start()
        service = HttpRelationService(
            IdpProperties(
                relation = IdpProperties.Relation(
                    baseUrl = "http://127.0.0.1:${server.address.port}",
                    connectTimeout = Duration.ofSeconds(1),
                ),
            ),
            parser,
        )
    }

    @AfterEach
    fun tearDown() {
        server.stop(0)
    }

    @Test
    fun returnsTenantMembershipFromRelationResponse() {
        respondWith(
            status = 200,
            body = """
                {
                  "tenant": {"id": "tenant-a", "role": "owner"},
                  "user": {"id": "user-123"},
                  "events": [
                    {"id": "event-1", "role": "staff"},
                    {"id": "event-2", "role": "owner"}
                  ]
                }
            """.trimIndent(),
        )

        val membership = service.getMembership("tenant-a", "user-123")

        assertEquals("tenant-a", membership.tenantId)
        assertEquals(RelationRole.OWNER, membership.tenantRole)
        assertEquals(
            listOf(
                EventMembership("event-1", RelationRole.STAFF),
                EventMembership("event-2", RelationRole.OWNER),
            ),
            membership.events,
        )
    }

    @Test
    fun convertsNotFoundToTenantNotFound() {
        respondWith(404, """{"error":"missing"}""")

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("tenant_not_found", exception.reason)
    }

    @Test
    fun rejectsMismatchedTenantOrUser() {
        respondWith(
            200,
            """
            {
              "tenant": {"id": "tenant-b", "role": "owner"},
              "user": {"id": "user-123"},
              "events": []
            }
            """.trimIndent(),
        )

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_response_invalid", exception.reason)
    }

    @Test
    fun rejectsMissingTenantRole() {
        respondWith(
            200,
            """
            {
              "tenant": {"id": "tenant-a"},
              "user": {"id": "user-123"},
              "events": []
            }
            """.trimIndent(),
        )

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("user_not_tenant_member", exception.reason)
    }

    @Test
    fun rejectsUnknownRole() {
        respondWith(
            200,
            """
            {
              "tenant": {"id": "tenant-a", "role": "admin"},
              "user": {"id": "user-123"},
              "events": []
            }
            """.trimIndent(),
        )

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_role_unknown", exception.reason)
    }

    @Test
    fun rejectsInvalidEventId() {
        respondWith(
            200,
            """
            {
              "tenant": {"id": "tenant-a", "role": "owner"},
              "user": {"id": "user-123"},
              "events": [{"id": " event-1", "role": "staff"}]
            }
            """.trimIndent(),
        )

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_response_invalid", exception.reason)
    }

    @Test
    fun convertsMalformedJsonToInvalidResponse() {
        respondWith(200, "{not-json")

        val exception = assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }
        assertEquals("relation_lookup_failed", exception.reason)
    }

    @Test
    fun validatesTenantIdBeforeCallingRelationService() {
        val exception = assertFailsWith<RuntimeException> {
            service.getMembership(" tenant-a", "user-123")
        }
        assertEquals("resource_invalid_format", exception.message)
    }

    private fun respondWith(status: Int, body: String) {
        server.createContext("/tenants/tenant-a/users/user-123") { exchange ->
            exchange.sendJson(status, body)
        }
    }

    private fun HttpExchange.sendJson(status: Int, body: String) {
        val bytes = body.toByteArray()
        responseHeaders.add("Content-Type", "application/json")
        sendResponseHeaders(status, bytes.size.toLong())
        responseBody.use { it.write(bytes) }
    }
}
