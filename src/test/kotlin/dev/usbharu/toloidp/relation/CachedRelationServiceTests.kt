package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.RelationRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.BeforeEach
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.simple.JdbcClient
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

@SpringBootTest(properties = ["tolo-idp.seed.enabled=false"])
class CachedRelationServiceTests(
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
    @Autowired private val jdbcClient: JdbcClient,
    @Autowired private val resourceParser: ResourceParser,
) {
    private val now = Instant.parse("2026-06-01T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val properties = IdpProperties(
        relation = IdpProperties.Relation(
            cache = IdpProperties.Relation.Cache(ttl = Duration.ofMinutes(5)),
        ),
    )

    @BeforeEach
    fun clearCache() {
        cacheRepository.deleteAll()
    }

    @Test
    fun firstLookupDelegatesAndWritesCacheRow() {
        val delegate = RecordingRelationService()
        val service = CachedRelationService(delegate, cacheRepository, properties, resourceParser, clock)

        val membership = service.getMembership("tenant-a", "user-123")

        assertEquals(sampleMembership("tenant-a"), membership)
        assertEquals(listOf("tenant-a" to "user-123"), delegate.calls)
        assertEquals(1, cacheRowCount())
    }

    @Test
    fun secondLookupWithinTtlUsesCacheWithoutDelegateCall() {
        val delegate = RecordingRelationService()
        val service = CachedRelationService(delegate, cacheRepository, properties, resourceParser, clock)

        service.getMembership("tenant-a", "user-123")
        service.getMembership("tenant-a", "user-123")

        assertEquals(listOf("tenant-a" to "user-123"), delegate.calls)
        assertEquals(1, cacheRowCount())
    }

    @Test
    fun expiredRowIsIgnoredAndRefreshed() {
        cacheRepository.put(
            tenantId = "tenant-a",
            userId = "user-123",
            membership = sampleMembership("tenant-a", "event-old"),
            cachedAt = now.minusSeconds(600),
            expiresAt = now.minusSeconds(1),
        )
        val delegate = RecordingRelationService()
        val service = CachedRelationService(delegate, cacheRepository, properties, resourceParser, clock)

        val membership = service.getMembership("tenant-a", "user-123")

        assertEquals(sampleMembership("tenant-a"), membership)
        assertEquals(listOf("tenant-a" to "user-123"), delegate.calls)
        assertEquals(sampleMembership("tenant-a"), cacheRepository.findValid("tenant-a", "user-123", now))
    }

    @Test
    fun delegateFailuresAreNotCached() {
        val delegate = RecordingRelationService(failure = RelationLookupException("relation_lookup_failed"))
        val service = CachedRelationService(delegate, cacheRepository, properties, resourceParser, clock)

        assertFailsWith<RelationLookupException> {
            service.getMembership("tenant-a", "user-123")
        }

        assertEquals(0, cacheRowCount())
        assertNull(cacheRepository.findValid("tenant-a", "user-123", now))
    }

    @Test
    fun purgeAllAndPurgeOneRemoveExpectedRows() {
        cacheRepository.put("tenant-a", "user-1", sampleMembership("tenant-a"), now, now.plusSeconds(300))
        cacheRepository.put("tenant-a", "user-2", sampleMembership("tenant-a"), now, now.plusSeconds(300))
        cacheRepository.put("tenant-b", "user-1", sampleMembership("tenant-b"), now, now.plusSeconds(300))

        cacheRepository.deleteOne("tenant-a", "user-1")

        assertNull(cacheRepository.findValid("tenant-a", "user-1", now))
        assertEquals(sampleMembership("tenant-a"), cacheRepository.findValid("tenant-a", "user-2", now))
        assertEquals(sampleMembership("tenant-b"), cacheRepository.findValid("tenant-b", "user-1", now))

        cacheRepository.deleteAll()

        assertEquals(0, cacheRowCount())
    }

    private fun cacheRowCount(): Int =
        jdbcClient.sql("select count(*) from idp_relation_membership_cache")
            .query(Int::class.java)
            .single()

    private fun sampleMembership(tenantId: String, eventId: String = "event-1"): TenantMembership =
        TenantMembership(
            tenantId = tenantId,
            tenantRole = RelationRole.OWNER,
            events = listOf(EventMembership(eventId, RelationRole.STAFF)),
        )

    private inner class RecordingRelationService(
        private val failure: RuntimeException? = null,
    ) : RelationService {
        val calls = mutableListOf<Pair<String, String>>()

        override fun getMembership(tenantId: String, userId: String): TenantMembership {
            calls += tenantId to userId
            failure?.let { throw it }
            return sampleMembership(tenantId)
        }
    }
}
