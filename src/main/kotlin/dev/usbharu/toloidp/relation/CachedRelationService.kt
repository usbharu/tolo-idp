package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Primary
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.Instant

@Service
@Primary
class CachedRelationService(
    @Qualifier("httpRelationService")
    private val delegate: RelationService,
    private val cacheRepository: RelationMembershipCacheRepository,
    private val properties: IdpProperties,
    private val resourceParser: ResourceParser,
    private val clock: Clock,
) : RelationService {
    override fun getMembership(tenantId: String, userId: String): TenantMembership {
        resourceParser.requireValidId(tenantId)
        val now = Instant.now(clock)
        cacheRepository.findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(tenantId, userId, now)
            ?.let { return it.membership }

        val membership = delegate.getMembership(tenantId, userId)
        val cacheId = RelationMembershipCacheId(tenantId, userId)
        cacheRepository.deleteById(cacheId)
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = cacheId,
                membership = membership,
                cachedAt = now,
                expiresAt = now.plus(properties.relation.cache.ttl),
            ),
        )
        return membership
    }
}
