package dev.usbharu.toloidp.client

import org.springframework.jdbc.core.simple.JdbcClient
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
    private val jdbcClient: JdbcClient,
) {
    fun findByClientId(clientId: String): ClientPolicy? {
        return jdbcClient.sql(
            """
            select client_id, client_type, allowed_grant_types, allowed_token_exchange_transitions,
                   allowed_audiences, allowed_scopes, tenant_access_ttl_seconds, event_access_ttl_seconds
            from idp_client_policy
            where client_id = :clientId
            """.trimIndent(),
        )
            .param("clientId", clientId)
            .query { rs, _ ->
                ClientPolicy(
                    clientId = rs.getString("client_id"),
                    clientType = ClientType.valueOf(rs.getString("client_type")),
                    allowedGrantTypes = splitCsv(rs.getString("allowed_grant_types")),
                    allowedTransitions = splitCsv(rs.getString("allowed_token_exchange_transitions")),
                    allowedAudiences = splitCsv(rs.getString("allowed_audiences")),
                    allowedScopes = splitCsv(rs.getString("allowed_scopes")),
                    tenantAccessTtl = Duration.ofSeconds(rs.getLong("tenant_access_ttl_seconds")),
                    eventAccessTtl = Duration.ofSeconds(rs.getLong("event_access_ttl_seconds")),
                )
            }
            .optional()
            .orElse(null)
    }

    private fun splitCsv(value: String?): Set<String> =
        value.orEmpty()
            .split(',')
            .filter { it.isNotEmpty() }
            .toSet()
}
