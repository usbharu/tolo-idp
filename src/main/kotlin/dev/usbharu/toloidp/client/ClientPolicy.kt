package dev.usbharu.toloidp.client

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import java.time.Duration

@Table("IDP_CLIENT_POLICY")
data class ClientPolicy(
    @Id
    val clientId: String,
    val clientType: ClientType,
    val allowedGrantTypes: Set<String>,
    @Column("ALLOWED_TOKEN_EXCHANGE_TRANSITIONS")
    val allowedTransitions: Set<String>,
    val allowedAudiences: Set<String>,
    val allowedScopes: Set<String>,
    @Column("TENANT_ACCESS_TTL_SECONDS")
    val tenantAccessTtl: Duration,
    @Column("EVENT_ACCESS_TTL_SECONDS")
    val eventAccessTtl: Duration,
) : Persistable<String> {
    @Transient
    var isNewEntity: Boolean = true

    override fun getId(): String = clientId

    override fun isNew(): Boolean = isNewEntity
}

enum class ClientType {
    CONFIDENTIAL,
    PUBLIC,
}

interface ClientPolicyRepository : CrudRepository<ClientPolicy, String> {
    fun findByClientId(clientId: String): ClientPolicy?
}
