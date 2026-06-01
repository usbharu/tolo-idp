package dev.usbharu.toloidp.audit

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.simple.JdbcClient
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertContains
import kotlin.test.assertEquals

@SpringBootTest(properties = ["tolo-idp.seed.enabled=false"])
class AuditServiceTests(
    @Autowired private val jdbcClient: JdbcClient,
    @Autowired private val objectMapper: tools.jackson.databind.ObjectMapper,
) {
    private val clock = Clock.fixed(Instant.parse("2026-06-01T00:00:00Z"), ZoneOffset.UTC)
    private val service by lazy { AuditService(jdbcClient, objectMapper, clock) }

    @BeforeEach
    fun setUp() {
        jdbcClient.sql("delete from idp_audit_log").update()
    }

    @Test
    fun recordsAuditEventAsColumnsAndJsonPayload() {
        service.record(
            TokenAuditEvent(
                requestId = "request-1",
                clientId = "client-123",
                subject = "user-123",
                sourceTokenUse = "tenant_access",
                requestedTokenUse = "event_access",
                requestedAudience = "backend-api",
                requestedResource = "https://api.example.com/tenants/tenant-a/events/event-1",
                requestedScope = listOf("events.read", "events.write"),
                issuedScope = listOf("events.read"),
                tenantId = "tenant-a",
                eventId = "event-1",
                result = "success",
                failureReason = null,
                sourceIp = "127.0.0.1",
                userAgent = "test-agent",
                issuedJti = "jti-1",
            ),
        )

        val row = jdbcClient.sql(
            """
            select request_id, client_id, subject, source_token_use, requested_token_use,
                   requested_audience, requested_resource, requested_scope, issued_scope,
                   tenant_id, event_id, result, failure_reason, source_ip, user_agent, issued_jti, payload
            from idp_audit_log
            """.trimIndent(),
        )
            .query { rs, _ ->
                mapOf(
                    "request_id" to rs.getString("request_id"),
                    "client_id" to rs.getString("client_id"),
                    "subject" to rs.getString("subject"),
                    "source_token_use" to rs.getString("source_token_use"),
                    "requested_token_use" to rs.getString("requested_token_use"),
                    "requested_audience" to rs.getString("requested_audience"),
                    "requested_resource" to rs.getString("requested_resource"),
                    "requested_scope" to rs.getString("requested_scope"),
                    "issued_scope" to rs.getString("issued_scope"),
                    "tenant_id" to rs.getString("tenant_id"),
                    "event_id" to rs.getString("event_id"),
                    "result" to rs.getString("result"),
                    "failure_reason" to rs.getString("failure_reason"),
                    "source_ip" to rs.getString("source_ip"),
                    "user_agent" to rs.getString("user_agent"),
                    "issued_jti" to rs.getString("issued_jti"),
                    "payload" to rs.getString("payload"),
                )
            }
            .single()

        assertEquals("request-1", row["request_id"])
        assertEquals("client-123", row["client_id"])
        assertEquals("user-123", row["subject"])
        assertEquals("tenant_access", row["source_token_use"])
        assertEquals("event_access", row["requested_token_use"])
        assertEquals("backend-api", row["requested_audience"])
        assertEquals("events.read events.write", row["requested_scope"])
        assertEquals("events.read", row["issued_scope"])
        assertEquals("tenant-a", row["tenant_id"])
        assertEquals("event-1", row["event_id"])
        assertEquals("success", row["result"])
        assertEquals(null, row["failure_reason"])
        assertEquals("127.0.0.1", row["source_ip"])
        assertEquals("test-agent", row["user_agent"])
        assertEquals("jti-1", row["issued_jti"])
        assertContains(row["payload"] as String, """"timestamp":"2026-06-01T00:00:00Z"""")
        assertContains(row["payload"] as String, """"requestedScope":["events.read","events.write"]""")
    }
}
