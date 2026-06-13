package dev.usbharu.toloidp.client

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.domain.Persistable
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.repository.CrudRepository
import org.springframework.transaction.annotation.Transactional
import java.time.Duration

@Table("idp_client_policy")
data class ClientPolicy(
    @Id
    @Column("client_id")
    val clientId: String,
    @Column("client_type")
    val clientType: ClientType,
    @Column("allowed_grant_types")
    val allowedGrantTypes: Set<String>,
    @Column("allowed_token_exchange_transitions")
    val allowedTransitions: Set<String>,
    @Column("allowed_audiences")
    val allowedAudiences: Set<String>,
    @Column("allowed_scopes")
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
    @Transactional(readOnly = true)
    @Query(
        """
        SELECT client_id, client_type, allowed_grant_types, allowed_token_exchange_transitions,
               allowed_audiences, allowed_scopes, tenant_access_ttl_seconds, event_access_ttl_seconds
        FROM idp_client_policy
        WHERE client_id = :clientId
        """,
    )
    fun findByClientId(clientId: String): ClientPolicy?
}
