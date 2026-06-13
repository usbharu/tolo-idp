package dev.usbharu.toloidp.security

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

@Table("idp_jti_denylist")
data class JtiDenylistEntry(
    @Id
    @Column("jti")
    val jti: String,
    @Column("expires_at")
    val expiresAt: Instant,
) : Persistable<String> {
    @Transient
    var isNewEntity: Boolean = false

    override fun getId(): String = jti

    override fun isNew(): Boolean = isNewEntity
}

interface JtiDenylistRepository : CrudRepository<JtiDenylistEntry, String> {
    @Transactional(readOnly = true)
    @Query(
        """
        SELECT CASE WHEN COUNT(*) > 0 THEN TRUE ELSE FALSE END
        FROM idp_jti_denylist
        WHERE jti = :jti AND expires_at > :now
        """,
    )
    fun existsByJtiAndExpiresAtAfter(jti: String, now: Instant): Boolean
}
