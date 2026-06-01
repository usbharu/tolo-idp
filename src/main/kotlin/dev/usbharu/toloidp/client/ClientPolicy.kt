package dev.usbharu.toloidp.client

import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.domain.Persistable
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository
import java.time.Duration

data class ClientPolicy(
    val clientId: String,
    val clientType: ClientType,
    val allowedGrantTypes: Set<String>,
    val allowedTransitions: Set<String>,
    val allowedAudiences: Set<String>,
    val allowedScopes: Set<String>,
    val tenantAccessTtl: Duration,
    val eventAccessTtl: Duration,
)

enum class ClientType {
    CONFIDENTIAL,
    PUBLIC,
}

@Repository
class ClientPolicyRepository(
    private val repository: ClientPolicyDataRepository,
) {
    fun findByClientId(clientId: String): ClientPolicy? =
        repository.findPolicyByClientId(clientId)?.toClientPolicy()

    fun save(policy: ClientPolicy): ClientPolicy =
        repository.save(policy.toEntity(isNew = !repository.existsById(policy.clientId))).toClientPolicy()

    fun deleteAll() {
        repository.deleteAll()
    }

    private fun splitCsv(value: String?): Set<String> =
        value.orEmpty()
            .split(',')
            .filter { it.isNotEmpty() }
            .toSet()

    private fun ClientPolicyEntity.toClientPolicy(): ClientPolicy =
        ClientPolicy(
            clientId = clientId,
            clientType = clientType,
            allowedGrantTypes = splitCsv(allowedGrantTypes),
            allowedTransitions = splitCsv(allowedTokenExchangeTransitions),
            allowedAudiences = splitCsv(allowedAudiences),
            allowedScopes = splitCsv(allowedScopes),
            tenantAccessTtl = Duration.ofSeconds(tenantAccessTtlSeconds),
            eventAccessTtl = Duration.ofSeconds(eventAccessTtlSeconds),
        )

    private fun ClientPolicy.toEntity(isNew: Boolean = false): ClientPolicyEntity =
        ClientPolicyEntity(
            clientId = clientId,
            clientType = clientType,
            allowedGrantTypes = allowedGrantTypes.joinToString(","),
            allowedTokenExchangeTransitions = allowedTransitions.joinToString(","),
            allowedAudiences = allowedAudiences.joinToString(","),
            allowedScopes = allowedScopes.joinToString(","),
            tenantAccessTtlSeconds = tenantAccessTtl.seconds,
            eventAccessTtlSeconds = eventAccessTtl.seconds,
        ).apply { isNewEntity = isNew }
}

@Table("IDP_CLIENT_POLICY")
data class ClientPolicyEntity(
    @Id
    val clientId: String,
    val clientType: ClientType,
    val allowedGrantTypes: String,
    val allowedTokenExchangeTransitions: String,
    val allowedAudiences: String,
    val allowedScopes: String,
    val tenantAccessTtlSeconds: Long,
    val eventAccessTtlSeconds: Long,
) : Persistable<String> {
    @Transient
    var isNewEntity: Boolean = false

    override fun getId(): String = clientId

    override fun isNew(): Boolean = isNewEntity
}

interface ClientPolicyDataRepository : CrudRepository<ClientPolicyEntity, String> {
    @Query("select * from idp_client_policy where client_id = :clientId")
    fun findPolicyByClientId(clientId: String): ClientPolicyEntity?
}
