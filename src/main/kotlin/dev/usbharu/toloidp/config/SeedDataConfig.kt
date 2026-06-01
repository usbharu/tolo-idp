package dev.usbharu.toloidp.config

import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.Duration
import java.util.UUID

@Configuration
class SeedDataConfig {
    @Bean
    fun seedDataRunner(
        properties: IdpProperties,
        jdbcClient: JdbcClient,
        passwordEncoder: PasswordEncoder,
        registeredClientRepository: RegisteredClientRepository,
    ): ApplicationRunner = ApplicationRunner {
        if (!properties.seed.enabled) {
            return@ApplicationRunner
        }

        val userCount = jdbcClient.sql("select count(*) from users where username = 'user-123'")
            .query(Int::class.java)
            .single()
        if (userCount == 0) {
            jdbcClient.sql("insert into users(username, password, enabled) values (:username, :password, true)")
                .param("username", "user-123")
                .param("password", passwordEncoder.encode(properties.seed.userPassword))
                .update()
            jdbcClient.sql("insert into authorities(username, authority) values (:username, :authority)")
                .param("username", "user-123")
                .param("authority", "ROLE_USER")
                .update()
        }

        if (registeredClientRepository.findByClientId("client-123") == null) {
            registeredClientRepository.save(
                RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("client-123")
                    .clientSecret(passwordEncoder.encode(properties.seed.clientSecret))
                    .clientName("Development confidential client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-123")
                    .scope("tenant.read")
                    .scope("tenant.write")
                    .scope("events.read")
                    .scope("events.write")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .tokenSettings(
                        TokenSettings.builder()
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                            .build(),
                    )
                    .build(),
            )
        }

        val policyCount = jdbcClient.sql("select count(*) from idp_client_policy where client_id = 'client-123'")
            .query(Int::class.java)
            .single()
        if (policyCount == 0) {
            jdbcClient.sql(
                """
                insert into idp_client_policy(
                    client_id, client_type, allowed_grant_types, allowed_token_exchange_transitions,
                    allowed_audiences, allowed_scopes, tenant_access_ttl_seconds, event_access_ttl_seconds
                ) values (
                    'client-123', 'CONFIDENTIAL', 'authorization_code,urn:ietf:params:oauth:grant-type:token-exchange',
                    'tenant_access:event_access', 'backend-api',
                    'tenant.read,tenant.write,events.read,events.write', 900, 600
                )
                """.trimIndent(),
            ).update()
        }
    }
}
