package dev.usbharu.toloidp.audit

import org.slf4j.LoggerFactory
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Service
import tools.jackson.databind.ObjectMapper
import java.time.Clock
import java.time.Instant

@Service
class AuditService(
    private val repository: AuditLogRepository,
    private val objectMapper: ObjectMapper,
    private val clock: Clock,
) {
    private val logger = LoggerFactory.getLogger("audit.token")

    fun record(event: TokenAuditEvent) {
        val timestamp = Instant.now(clock)
        val payload = objectMapper.writeValueAsString(event.copy(timestamp = timestamp.toString()))
        logger.info(payload)
        repository.save(
            AuditLogRecord(
                timestamp = timestamp,
                requestId = event.requestId,
                clientId = event.clientId,
                subject = event.subject,
                sourceTokenUse = event.sourceTokenUse,
                requestedTokenUse = event.requestedTokenUse,
                requestedAudience = event.requestedAudience,
                requestedResource = event.requestedResource,
                requestedScope = event.requestedScope.joinToString(" "),
                issuedScope = event.issuedScope.joinToString(" "),
                tenantId = event.tenantId,
                eventId = event.eventId,
                result = event.result,
                failureReason = event.failureReason,
                sourceIp = event.sourceIp,
                userAgent = event.userAgent,
                issuedJti = event.issuedJti,
                payload = payload,
            ),
        )
    }
}

@Table("idp_audit_log")
data class AuditLogRecord(
    @Id
    val id: Long? = null,
    val timestamp: Instant,
    val requestId: String?,
    val clientId: String?,
    val subject: String?,
    val sourceTokenUse: String?,
    val requestedTokenUse: String?,
    val requestedAudience: String?,
    val requestedResource: String?,
    val requestedScope: String,
    val issuedScope: String,
    val tenantId: String?,
    val eventId: String?,
    val result: String,
    val failureReason: String?,
    val sourceIp: String?,
    val userAgent: String?,
    val issuedJti: String?,
    val payload: String,
)

interface AuditLogRepository : CrudRepository<AuditLogRecord, Long>

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
