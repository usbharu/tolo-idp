package dev.usbharu.toloidp.relation

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import java.time.Instant

data class RelationMembershipCacheId(
    val tenantId: String,
    val userId: String,
)

@Table("idp_relation_membership_cache")
data class RelationMembershipCache(
    @Id
    val cacheId: RelationMembershipCacheId,
    @Column("payload")
    val membership: TenantMembership,
    val cachedAt: Instant,
    val expiresAt: Instant,
) : Persistable<RelationMembershipCacheId> {
    @Transient
    var isNewEntity: Boolean = true

    override fun getId(): RelationMembershipCacheId = cacheId

    override fun isNew(): Boolean = isNewEntity
}

interface RelationMembershipCacheRepository : CrudRepository<RelationMembershipCache, RelationMembershipCacheId> {
    fun findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(
        tenantId: String,
        userId: String,
        now: Instant,
    ): RelationMembershipCache?
}
