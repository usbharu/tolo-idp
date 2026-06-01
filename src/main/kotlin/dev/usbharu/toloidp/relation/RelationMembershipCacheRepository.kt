package dev.usbharu.toloidp.relation

import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.readValue
import java.time.Instant

@Repository
class RelationMembershipCacheRepository(
    private val jdbcClient: JdbcClient,
    private val objectMapper: ObjectMapper,
) {
    fun findValid(tenantId: String, userId: String, now: Instant): TenantMembership? =
        jdbcClient.sql(
            """
            select payload
            from idp_relation_membership_cache
            where tenant_id = :tenantId
              and user_id = :userId
              and expires_at > :now
            """.trimIndent(),
        )
            .param("tenantId", tenantId)
            .param("userId", userId)
            .param("now", now)
            .query(String::class.java)
            .optional()
            .map { objectMapper.readValue<TenantMembership>(it) }
            .orElse(null)

    @Transactional
    fun put(
        tenantId: String,
        userId: String,
        membership: TenantMembership,
        cachedAt: Instant,
        expiresAt: Instant,
    ) {
        deleteOne(tenantId, userId)
        jdbcClient.sql(
            """
            insert into idp_relation_membership_cache(tenant_id, user_id, payload, cached_at, expires_at)
            values (:tenantId, :userId, :payload, :cachedAt, :expiresAt)
            """.trimIndent(),
        )
            .param("tenantId", tenantId)
            .param("userId", userId)
            .param("payload", objectMapper.writeValueAsString(membership))
            .param("cachedAt", cachedAt)
            .param("expiresAt", expiresAt)
            .update()
    }

    fun deleteAll(): Int =
        jdbcClient.sql("delete from idp_relation_membership_cache")
            .update()

    fun deleteOne(tenantId: String, userId: String): Int =
        jdbcClient.sql(
            """
            delete from idp_relation_membership_cache
            where tenant_id = :tenantId and user_id = :userId
            """.trimIndent(),
        )
            .param("tenantId", tenantId)
            .param("userId", userId)
            .update()
}
