package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import org.slf4j.LoggerFactory
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
        log.trace("getMembership started: tenantId={}, userId={}", tenantId, userId)
        resourceParser.requireValidId(tenantId)
        val now = Instant.now(clock)
        cacheRepository.findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(tenantId, userId, now)
            ?.let {
                log.debug(
                    "Relation membership cache hit: tenantId={}, userId={}, expiresAt={}",
                    tenantId,
                    userId,
                    it.expiresAt,
                )
                log.trace("getMembership completed from cache: tenantId={}, userId={}", tenantId, userId)
                return it.membership
            }

        log.debug("Relation membership cache miss: tenantId={}, userId={}", tenantId, userId)
        val membership = delegate.getMembership(tenantId, userId)
        val cacheId = RelationMembershipCacheId(tenantId, userId)
        cacheRepository.deleteById(cacheId)
        val expiresAt = now.plus(properties.relation.cache.ttl)
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = cacheId,
                membership = membership,
                cachedAt = now,
                expiresAt = expiresAt,
            ),
        )
        log.debug(
            "Relation membership cached: tenantId={}, userId={}, eventCount={}, expiresAt={}",
            tenantId,
            userId,
            membership.events.size,
            expiresAt,
        )
        log.trace("getMembership completed after delegate lookup: tenantId={}, userId={}", tenantId, userId)
        return membership
    }

    companion object {
        private val log = LoggerFactory.getLogger(CachedRelationService::class.java)
    }
}
