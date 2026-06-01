package dev.usbharu.toloidp.audit

import org.slf4j.LoggerFactory
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.stereotype.Service
import tools.jackson.databind.ObjectMapper
import java.time.Clock
import java.time.Instant

@Service
class AuditService(
    private val jdbcClient: JdbcClient,
    private val objectMapper: ObjectMapper,
    private val clock: Clock,
) {
    private val logger = LoggerFactory.getLogger("audit.token")

    fun record(event: TokenAuditEvent) {
        val timestamp = Instant.now(clock)
        val payload = objectMapper.writeValueAsString(event.copy(timestamp = timestamp.toString()))
        logger.info(payload)
        jdbcClient.sql(
            """
            insert into idp_audit_log(
                timestamp, request_id, client_id, subject, source_token_use, requested_token_use,
                requested_audience, requested_resource, requested_scope, issued_scope,
                tenant_id, event_id, result, failure_reason, source_ip, user_agent, issued_jti, payload
            ) values (
                :timestamp, :requestId, :clientId, :subject, :sourceTokenUse, :requestedTokenUse,
                :requestedAudience, :requestedResource, :requestedScope, :issuedScope,
                :tenantId, :eventId, :result, :failureReason, :sourceIp, :userAgent, :issuedJti, :payload
            )
            """.trimIndent(),
        )
            .param("timestamp", timestamp)
            .param("requestId", event.requestId)
            .param("clientId", event.clientId)
            .param("subject", event.subject)
            .param("sourceTokenUse", event.sourceTokenUse)
            .param("requestedTokenUse", event.requestedTokenUse)
            .param("requestedAudience", event.requestedAudience)
            .param("requestedResource", event.requestedResource)
            .param("requestedScope", event.requestedScope.joinToString(" "))
            .param("issuedScope", event.issuedScope.joinToString(" "))
            .param("tenantId", event.tenantId)
            .param("eventId", event.eventId)
            .param("result", event.result)
            .param("failureReason", event.failureReason)
            .param("sourceIp", event.sourceIp)
            .param("userAgent", event.userAgent)
            .param("issuedJti", event.issuedJti)
            .param("payload", payload)
            .update()
    }
}

data class TokenAuditEvent(
    val timestamp: String? = null,
    val requestId: String? = null,
    val clientId: String? = null,
    val subject: String? = null,
    val sourceTokenUse: String? = null,
    val requestedTokenUse: String? = null,
    val requestedAudience: String? = null,
    val requestedResource: String? = null,
    val requestedScope: List<String> = emptyList(),
    val issuedScope: List<String> = emptyList(),
    val tenantId: String? = null,
    val eventId: String? = null,
    val result: String,
    val failureReason: String? = null,
    val sourceIp: String? = null,
    val userAgent: String? = null,
    val issuedJti: String? = null,
)
