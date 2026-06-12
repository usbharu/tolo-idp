package dev.usbharu.toloidp.security

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import java.time.Instant

@Table("idp_jti_denylist")
data class JtiDenylistEntry(
    @Id
    val jti: String,
    val expiresAt: Instant,
) : Persistable<String> {
    @Transient
    var isNewEntity: Boolean = false

    override fun getId(): String = jti

    override fun isNew(): Boolean = isNewEntity
}

interface JtiDenylistRepository : CrudRepository<JtiDenylistEntry, String> {
    fun existsByJtiAndExpiresAtAfter(jti: String, now: Instant): Boolean
}
