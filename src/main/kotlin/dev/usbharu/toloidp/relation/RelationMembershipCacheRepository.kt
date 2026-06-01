package dev.usbharu.toloidp.relation

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.readValue
import java.time.Instant

@Repository
class RelationMembershipCacheRepository(
    private val repository: RelationMembershipCacheDataRepository,
    private val objectMapper: ObjectMapper,
) {
    fun findValid(tenantId: String, userId: String, now: Instant): TenantMembership? =
        repository.findById(RelationMembershipCacheId(tenantId, userId))
            .filter { it.expiresAt > now }
            .orElse(null)
            ?.let { objectMapper.readValue<TenantMembership>(it.payload) }

    @Transactional
    fun put(
        tenantId: String,
        userId: String,
        membership: TenantMembership,
        cachedAt: Instant,
        expiresAt: Instant,
    ) {
        val id = RelationMembershipCacheId(tenantId, userId)
        repository.deleteById(id)
        repository.save(
            RelationMembershipCacheEntity(
                cacheId = id,
                payload = objectMapper.writeValueAsString(membership),
                cachedAt = cachedAt,
                expiresAt = expiresAt,
            ).apply { isNewEntity = true },
        )
    }

    fun deleteAll(): Int =
        repository.deleteAll().let { 0 }

    fun deleteOne(tenantId: String, userId: String): Int =
        repository.deleteById(RelationMembershipCacheId(tenantId, userId)).let { 0 }

    fun count(): Long =
        repository.count()
}

data class RelationMembershipCacheId(
    val tenantId: String,
    val userId: String,
)

@Table("IDP_RELATION_MEMBERSHIP_CACHE")
data class RelationMembershipCacheEntity(
    @Id
    val cacheId: RelationMembershipCacheId,
    val payload: String,
    val cachedAt: Instant,
    val expiresAt: Instant,
) : Persistable<RelationMembershipCacheId> {
    @Transient
    var isNewEntity: Boolean = false

    override fun getId(): RelationMembershipCacheId = cacheId

    override fun isNew(): Boolean = isNewEntity
}

interface RelationMembershipCacheDataRepository : CrudRepository<RelationMembershipCacheEntity, RelationMembershipCacheId>
