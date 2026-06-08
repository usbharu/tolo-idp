package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.scope.RelationRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509
import java.math.BigInteger
import java.net.URI
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal

@SpringBootTest(
    properties = [
        "tolo-idp.seed.enabled=false",
        "tolo-idp.relation.cache.admin-subjects=cache-admin",
    ],
)
@AutoConfigureMockMvc
class RelationCacheControllerSecurityTests(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val cacheRepository: RelationMembershipCacheRepository,
) {
    private val adminCertificate = TestX509Certificate("cache-admin")
    private val deniedCertificate = TestX509Certificate("not-admin")

    @BeforeEach
    fun clearCache() {
        cacheRepository.deleteAll()
    }

    @Test
    fun purgeEndpointsRequireX509Authentication() {
        mockMvc.perform(delete("/internal/relation-cache"))
            .andExpect(status().is4xxClientError)
    }

    @Test
    fun unlistedCertificatePrincipalIsForbidden() {
        mockMvc.perform(delete("/internal/relation-cache").with(x509(deniedCertificate)))
            .andExpect(status().isForbidden)
    }

    @Test
    fun allowListedCertificatePrincipalCanPurgeAll() {
        cacheMembership("tenant-a", "user-1", sampleMembership("tenant-a"))
        cacheMembership("tenant-b", "user-2", sampleMembership("tenant-b"))

        mockMvc.perform(delete("/internal/relation-cache").with(x509(adminCertificate)))
            .andExpect(status().isNoContent)

        kotlin.test.assertNull(cachedMembership("tenant-a", "user-1"))
        kotlin.test.assertNull(cachedMembership("tenant-b", "user-2"))
    }

    @Test
    fun allowListedCertificatePrincipalCanPurgeOne() {
        cacheMembership("tenant-a", "user-1", sampleMembership("tenant-a"))
        cacheMembership("tenant-a", "user-2", sampleMembership("tenant-a"))

        mockMvc.perform(
            delete("/internal/relation-cache/tenants/tenant-a/users/user-1")
                .with(x509(adminCertificate)),
        )
            .andExpect(status().isNoContent)

        kotlin.test.assertNull(cachedMembership("tenant-a", "user-1"))
        kotlin.test.assertEquals(sampleMembership("tenant-a"), cachedMembership("tenant-a", "user-2"))
    }

    @Test
    fun invalidTenantIdIsRejectedAndDoesNotPurgeEntries() {
        cacheMembership("tenant-a", "user-1", sampleMembership("tenant-a"))

        mockMvc.perform(
            delete("/internal/relation-cache/tenants/%20tenant-a/users/user-1")
                .with(x509(adminCertificate)),
        )
            .andExpect(status().isBadRequest)

        kotlin.test.assertEquals(sampleMembership("tenant-a"), cachedMembership("tenant-a", "user-1"))
    }

    @Test
    fun purgeOneUsesUserIdWithoutTrimming() {
        cacheMembership("tenant-a", " user-1", sampleMembership("tenant-a"))
        cacheMembership("tenant-a", "user-1", sampleMembership("tenant-a"))

        mockMvc.perform(
            delete(URI.create("/internal/relation-cache/tenants/tenant-a/users/%20user-1"))
                .with(x509(adminCertificate)),
        )
            .andExpect(status().isNoContent)

        kotlin.test.assertNull(cachedMembership("tenant-a", " user-1"))
        kotlin.test.assertEquals(sampleMembership("tenant-a"), cachedMembership("tenant-a", "user-1"))
    }

    private fun cacheMembership(tenantId: String, userId: String, membership: TenantMembership) {
        cacheRepository.save(
            RelationMembershipCache(
                cacheId = RelationMembershipCacheId(tenantId, userId),
                membership = membership,
                cachedAt = Instant.EPOCH,
                expiresAt = future,
            ),
        )
    }

    private fun cachedMembership(tenantId: String, userId: String): TenantMembership? =
        cacheRepository.findByCacheIdTenantIdAndCacheIdUserIdAndExpiresAtAfter(tenantId, userId, Instant.now())
            ?.membership

    private fun sampleMembership(tenantId: String): TenantMembership =
        TenantMembership(
            tenantId = tenantId,
            tenantRole = RelationRole.OWNER,
            events = listOf(EventMembership("event-1", RelationRole.STAFF)),
        )

    private companion object {
        val future: Instant = Instant.parse("2030-01-01T00:00:00Z")
    }

    private class TestX509Certificate(
        private val commonName: String,
    ) : X509Certificate() {
        private val principal = X500Principal("CN=$commonName")

        override fun getSubjectX500Principal(): X500Principal = principal

        override fun getSubjectDN(): Principal = principal

        override fun getIssuerX500Principal(): X500Principal = X500Principal("CN=test-issuer")

        override fun getIssuerDN(): Principal = issuerX500Principal

        override fun checkValidity() = Unit

        override fun checkValidity(date: Date?) = Unit

        override fun getVersion(): Int = 3

        override fun getSerialNumber(): BigInteger = BigInteger.ONE

        override fun getNotBefore(): Date = Date.from(Instant.EPOCH)

        override fun getNotAfter(): Date = Date.from(future)

        override fun getTBSCertificate(): ByteArray = ByteArray(0)

        override fun getSignature(): ByteArray = ByteArray(0)

        override fun getSigAlgName(): String = "NONE"

        override fun getSigAlgOID(): String = "1.2.3.4"

        override fun getSigAlgParams(): ByteArray? = null

        override fun getIssuerUniqueID(): BooleanArray? = null

        override fun getSubjectUniqueID(): BooleanArray? = null

        override fun getKeyUsage(): BooleanArray? = null

        override fun getBasicConstraints(): Int = -1

        override fun getEncoded(): ByteArray = ByteArray(0)

        override fun verify(key: PublicKey?) = Unit

        override fun verify(key: PublicKey?, sigProvider: String?) = Unit

        override fun toString(): String = "TestX509Certificate($commonName)"

        override fun getPublicKey(): PublicKey? = null

        override fun hasUnsupportedCriticalExtension(): Boolean = false

        override fun getCriticalExtensionOIDs(): Set<String>? = null

        override fun getNonCriticalExtensionOIDs(): Set<String>? = null

        override fun getExtensionValue(oid: String?): ByteArray? = null
    }
}
