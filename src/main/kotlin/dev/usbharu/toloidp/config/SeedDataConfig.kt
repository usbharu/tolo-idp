package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.client.ClientPolicy
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.client.ClientType
import dev.usbharu.toloidp.relation.EventMembership
import dev.usbharu.toloidp.relation.RelationMembershipCache
import dev.usbharu.toloidp.relation.RelationMembershipCacheId
import dev.usbharu.toloidp.relation.RelationMembershipCacheRepository
import dev.usbharu.toloidp.relation.TenantMembership
import dev.usbharu.toloidp.scope.RelationRole
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.provisioning.UserDetailsManager
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Duration
import java.util.UUID

@Configuration
class SeedDataConfig {
    @Bean
    fun seedDataRunner(
        properties: IdpProperties,
        passwordEncoder: PasswordEncoder,
        userDetailsManager: UserDetailsManager,
        registeredClientRepository: RegisteredClientRepository,
        clientPolicyRepository: ClientPolicyRepository,
        relationMembershipCacheRepository: RelationMembershipCacheRepository,
        clock: Clock,
    ): ApplicationRunner =
        SeedDataRunner(
            properties,
            passwordEncoder,
            userDetailsManager,
            registeredClientRepository,
            clientPolicyRepository,
            relationMembershipCacheRepository,
            clock,
        )
}

open class SeedDataRunner(
    private val properties: IdpProperties,
    private val passwordEncoder: PasswordEncoder,
    private val userDetailsManager: UserDetailsManager,
    private val registeredClientRepository: RegisteredClientRepository,
    private val clientPolicyRepository: ClientPolicyRepository,
    private val relationMembershipCacheRepository: RelationMembershipCacheRepository,
    private val clock: Clock,
) : ApplicationRunner {
    @Transactional
    override fun run(args: org.springframework.boot.ApplicationArguments) {
        seed()
    }

    private fun seed() {
        if (!properties.seed.enabled) {
            return
        }

        if (!userDetailsManager.userExists("user-123")) {
            userDetailsManager.createUser(
                User.withUsername("user-123")
                    .password(passwordEncoder.encode(properties.seed.userPassword))
                    .roles("USER")
                    .build(),
            )
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

        if (clientPolicyRepository.findByClientId("client-123") == null) {
            clientPolicyRepository.save(
                ClientPolicy(
                    clientId = "client-123",
                    clientType = ClientType.CONFIDENTIAL,
                    allowedGrantTypes = setOf(
                        AuthorizationGrantType.AUTHORIZATION_CODE.value,
                        AuthorizationGrantType.TOKEN_EXCHANGE.value,
                    ),
                    allowedTransitions = setOf("tenant_access:event_access"),
                    allowedAudiences = setOf("backend-api"),
                    allowedScopes = setOf("tenant.read", "tenant.write", "events.read", "events.write"),
                    tenantAccessTtl = Duration.ofSeconds(900),
                    eventAccessTtl = Duration.ofSeconds(600),
                ),
            )
        }

        seedRelationMembership()
    }

    private fun seedRelationMembership() {
        val cacheId = RelationMembershipCacheId("tenant-a", "user-123")
        val now = clock.instant()
        val cache = RelationMembershipCache(
            cacheId = cacheId,
            membership = TenantMembership(
                tenantId = "tenant-a",
                tenantRole = RelationRole.OWNER,
                events = listOf(EventMembership("event-1", RelationRole.STAFF)),
            ),
            cachedAt = now,
            expiresAt = now.plus(properties.seed.membershipCacheTtl),
        )
        if (relationMembershipCacheRepository.existsById(cacheId)) {
            cache.isNewEntity = false
        }
        relationMembershipCacheRepository.save(cache)
    }
}
