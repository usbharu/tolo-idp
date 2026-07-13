package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.annotation.DirtiesContext
import java.time.Clock
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class SeedDataConfigTests(
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val clock: Clock,
) {
    @Test
    fun seedsDevelopmentTenantMembership() {
        val cache = cacheRepository.findById(RelationMembershipCacheId("tenant-a", "user-123")).orElse(null)

        assertNotNull(cache)
        assertEquals("tenant-a", cache.membership.tenantId)
        assertEquals(RelationRole.OWNER, cache.membership.tenantRole)
        assertEquals("event-1", cache.membership.events.single().eventId)
        assertEquals(RelationRole.STAFF, cache.membership.events.single().role)
        assertTrue(cache.expiresAt.isAfter(clock.instant()))
    }
}
