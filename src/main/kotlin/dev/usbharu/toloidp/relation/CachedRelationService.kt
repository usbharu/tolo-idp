package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.logging.structuredDebug
import dev.usbharu.toloidp.logging.structuredTrace
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
        log.structuredTrace("Relation membership lookup started", "event" to "relation_membership_lookup_started", "tenant_id" to tenantId, "subject" to userId)
        resourceParser.requireValidId(tenantId)
        val now = Instant.now(clock)
        cacheRepository.findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(tenantId, userId, now)
            ?.let {
                log.structuredDebug(
                    "Relation membership cache hit",
                    "event" to "relation_membership_cache_lookup",
                    "tenant_id" to tenantId,
                    "subject" to userId,
                    "cache_hit" to true,
                    "expires_at" to it.expiresAt,
                )
                log.structuredTrace("Relation membership lookup completed", "event" to "relation_membership_lookup_completed", "tenant_id" to tenantId, "subject" to userId, "cache_hit" to true)
                return it.membership
            }

        log.structuredDebug(
            "Relation membership cache miss",
            "event" to "relation_membership_cache_lookup",
            "tenant_id" to tenantId,
            "subject" to userId,
            "cache_hit" to false,
        )
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
        log.structuredDebug(
            "Relation membership cached",
            "event" to "relation_membership_cached",
            "tenant_id" to tenantId,
            "subject" to userId,
            "event_count" to membership.events.size,
            "expires_at" to expiresAt,
        )
        log.structuredTrace("Relation membership lookup completed", "event" to "relation_membership_lookup_completed", "tenant_id" to tenantId, "subject" to userId, "cache_hit" to false)
        return membership
    }

    companion object {
        private val log = LoggerFactory.getLogger(CachedRelationService::class.java)
    }
}
