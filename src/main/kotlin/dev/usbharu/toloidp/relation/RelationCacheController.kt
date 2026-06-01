package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.resource.ResourceParser
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
        cacheRepository.deleteAll()
        return ResponseEntity.noContent().build()
    }

    @DeleteMapping("/tenants/{tenantId}/users/{userId}")
    fun purgeOne(
        @PathVariable tenantId: String,
        @PathVariable userId: String,
    ): ResponseEntity<Void> {
        resourceParser.requireValidId(tenantId)
        cacheRepository.deleteOne(tenantId, userId)
        return ResponseEntity.noContent().build()
    }
}
