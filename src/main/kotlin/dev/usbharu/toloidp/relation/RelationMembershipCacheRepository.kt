package dev.usbharu.toloidp.relation

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

data class RelationMembershipCacheId(
    @Column("tenant_id")
    val tenantId: String,
    @Column("user_id")
    val userId: String,
)

@Table("idp_relation_membership_cache")
data class RelationMembershipCache(
    @Id
    val cacheId: RelationMembershipCacheId,
    @Column("payload")
    val membership: TenantMembership,
    @Column("cached_at")
    val cachedAt: Instant,
    @Column("expires_at")
    val expiresAt: Instant,
) : Persistable<RelationMembershipCacheId> {
    @Transient
    var isNewEntity: Boolean = true

    override fun getId(): RelationMembershipCacheId = cacheId

    override fun isNew(): Boolean = isNewEntity
}

interface RelationMembershipCacheRepository : CrudRepository<RelationMembershipCache, RelationMembershipCacheId> {
    @Transactional(readOnly = true)
    @Query(
        """
        SELECT tenant_id, user_id, payload, cached_at, expires_at
        FROM idp_relation_membership_cache
        WHERE tenant_id = :tenantId AND user_id = :userId AND expires_at > :now
        """,
    )
    fun findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(
        tenantId: String,
        userId: String,
        now: Instant,
    ): RelationMembershipCache?
}
