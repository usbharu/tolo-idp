package dev.usbharu.toloidp.client

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.simple.JdbcClient
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertNull

@SpringBootTest(
    properties = [
        "tolo-idp.seed.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:client-policy-tests;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
    ],
)
class ClientPolicyRepositoryTests(
    @Autowired private val repository: ClientPolicyRepository,
    @Autowired private val jdbcClient: JdbcClient,
) {
    @BeforeEach
    fun setUp() {
        jdbcClient.sql("delete from idp_client_policy").update()
    }

    @Test
    fun mapsClientPolicyCsvValuesAndTtls() {
        jdbcClient.sql(
            """
            insert into idp_client_policy(
                client_id, client_type, allowed_grant_types, allowed_token_exchange_transitions,
                allowed_audiences, allowed_scopes, tenant_access_ttl_seconds, event_access_ttl_seconds
            ) values (
                'client-a', 'CONFIDENTIAL', 'authorization_code,urn:ietf:params:oauth:grant-type:token-exchange',
                'tenant_access:event_access', 'backend-api,events-api',
                'tenant.read,events.read,events.write', 900, 600
            )
            """.trimIndent(),
        ).update()

        val policy = repository.findByClientId("client-a")

        assertEquals(
            ClientPolicy(
                clientId = "client-a",
                clientType = ClientType.CONFIDENTIAL,
                allowedGrantTypes = setOf("authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"),
                allowedTransitions = setOf("tenant_access:event_access"),
                allowedAudiences = setOf("backend-api", "events-api"),
                allowedScopes = setOf("tenant.read", "events.read", "events.write"),
                tenantAccessTtl = Duration.ofSeconds(900),
                eventAccessTtl = Duration.ofSeconds(600),
            ),
            policy,
        )
    }

    @Test
    fun mapsEmptyCsvColumnsToEmptySets() {
        jdbcClient.sql(
            """
            insert into idp_client_policy(
                client_id, client_type, allowed_grant_types, allowed_token_exchange_transitions,
                allowed_audiences, allowed_scopes, tenant_access_ttl_seconds, event_access_ttl_seconds
            ) values (
                'client-public', 'PUBLIC', '', '', '', '', 1, 2
            )
            """.trimIndent(),
        ).update()

        val policy = repository.findByClientId("client-public")

        assertEquals(ClientType.PUBLIC, policy?.clientType)
        assertEquals(emptySet(), policy?.allowedGrantTypes)
        assertEquals(emptySet(), policy?.allowedTransitions)
        assertEquals(emptySet(), policy?.allowedAudiences)
        assertEquals(emptySet(), policy?.allowedScopes)
        assertEquals(Duration.ofSeconds(1), policy?.tenantAccessTtl)
        assertEquals(Duration.ofSeconds(2), policy?.eventAccessTtl)
    }

    @Test
    fun returnsNullForUnknownClient() {
        assertNull(repository.findByClientId("missing-client"))
    }
}
