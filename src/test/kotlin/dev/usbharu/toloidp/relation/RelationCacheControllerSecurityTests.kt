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
        cacheRepository.put("tenant-a", "user-1", sampleMembership("tenant-a"), Instant.EPOCH, future)
        cacheRepository.put("tenant-b", "user-2", sampleMembership("tenant-b"), Instant.EPOCH, future)

        mockMvc.perform(delete("/internal/relation-cache").with(x509(adminCertificate)))
            .andExpect(status().isNoContent)

        kotlin.test.assertNull(cacheRepository.findValid("tenant-a", "user-1", Instant.now()))
        kotlin.test.assertNull(cacheRepository.findValid("tenant-b", "user-2", Instant.now()))
    }

    @Test
    fun allowListedCertificatePrincipalCanPurgeOne() {
        cacheRepository.put("tenant-a", "user-1", sampleMembership("tenant-a"), Instant.EPOCH, future)
        cacheRepository.put("tenant-a", "user-2", sampleMembership("tenant-a"), Instant.EPOCH, future)

        mockMvc.perform(
            delete("/internal/relation-cache/tenants/tenant-a/users/user-1")
                .with(x509(adminCertificate)),
        )
            .andExpect(status().isNoContent)

        kotlin.test.assertNull(cacheRepository.findValid("tenant-a", "user-1", Instant.now()))
        kotlin.test.assertEquals(sampleMembership("tenant-a"), cacheRepository.findValid("tenant-a", "user-2", Instant.now()))
    }

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
