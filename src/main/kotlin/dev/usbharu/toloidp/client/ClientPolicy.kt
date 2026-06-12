package dev.usbharu.toloidp.client

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import java.time.Duration

@Table("idp_client_policy")
data class ClientPolicy(
    @Id
    val clientId: String,
    val clientType: ClientType,
    val allowedGrantTypes: Set<String>,
    @Column("allowed_token_exchange_transitions")
    val allowedTransitions: Set<String>,
    val allowedAudiences: Set<String>,
    val allowedScopes: Set<String>,
    @Column("tenant_access_ttl_seconds")
    val tenantAccessTtl: Duration,
    @Column("event_access_ttl_seconds")
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
