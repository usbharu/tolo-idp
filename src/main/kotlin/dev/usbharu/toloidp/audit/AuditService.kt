package dev.usbharu.toloidp.audit

import org.slf4j.LoggerFactory
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional
import tools.jackson.databind.ObjectMapper
import java.time.Clock
import java.time.Instant

/**
 * トークン発行・交換に関する監査イベントを永続化し、監査ログへ出力するサービス。
 *
 * OAuth2 の外部エラーレスポンスへ出さない成功・失敗理由を、内部監査用の記録として保持する。
 */
@Service
class AuditService(
    private val repository: AuditLogRepository,
    private val objectMapper: ObjectMapper,
    private val clock: Clock,
) {
    private val logger = LoggerFactory.getLogger("audit.token")

    /**
     * トークン監査イベントを独立したトランザクションで保存し、同じ構造化ペイロードを監査ロガーへ出力する。
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
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
    @Column("id")
    val id: Long? = null,
    @Column("timestamp")
    val timestamp: Instant,
    @Column("request_id")
    val requestId: String?,
    @Column("client_id")
    val clientId: String?,
    @Column("subject")
    val subject: String?,
    @Column("source_token_use")
    val sourceTokenUse: String?,
    @Column("requested_token_use")
    val requestedTokenUse: String?,
    @Column("requested_audience")
    val requestedAudience: String?,
    @Column("requested_resource")
    val requestedResource: String?,
    @Column("requested_scope")
    val requestedScope: String,
    @Column("issued_scope")
    val issuedScope: String,
    @Column("tenant_id")
    val tenantId: String?,
    @Column("event_id")
    val eventId: String?,
    @Column("result")
    val result: String,
    @Column("failure_reason")
    val failureReason: String?,
    @Column("source_ip")
    val sourceIp: String?,
    @Column("user_agent")
    val userAgent: String?,
    @Column("issued_jti")
    val issuedJti: String?,
    @Column("payload")
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
