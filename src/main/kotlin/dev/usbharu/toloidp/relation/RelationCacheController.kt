package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.resource.ResourceParser
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/internal/relation-cache")
class RelationCacheController(
    private val cacheRepository: RelationMembershipCacheRepository,
    private val resourceParser: ResourceParser,
) {
    @DeleteMapping
    fun purgeAll(): ResponseEntity<Void> {
        val cacheCount = cacheRepository.count()
        log.info("Relation membership cache purge started: target=all, cacheCount={}", cacheCount)
        cacheRepository.deleteAll()
        log.info("Relation membership cache purge completed: target=all, purgedCount={}", cacheCount)
        return ResponseEntity.noContent().build()
    }

    @DeleteMapping("/tenants/{tenantId}/users/{userId}")
    fun purgeOne(
        @PathVariable tenantId: String,
        @PathVariable userId: String,
    ): ResponseEntity<Void> {
        resourceParser.requireValidId(tenantId)
        log.info("Relation membership cache purge started: tenantId={}, userId={}", tenantId, userId)
        cacheRepository.deleteById(RelationMembershipCacheId(tenantId, userId))
        log.info("Relation membership cache purge completed: tenantId={}, userId={}", tenantId, userId)
        return ResponseEntity.noContent().build()
    }

    companion object {
        private val log = LoggerFactory.getLogger(RelationCacheController::class.java)
    }
}
