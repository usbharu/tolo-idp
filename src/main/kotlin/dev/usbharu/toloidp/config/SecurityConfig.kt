package dev.usbharu.toloidp.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import dev.usbharu.toloidp.audit.AuditService
import dev.usbharu.toloidp.client.ClientPolicyRepository
import dev.usbharu.toloidp.relation.RelationService
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.scope.ScopePolicy
import dev.usbharu.toloidp.security.JtiDenylistRepository
import dev.usbharu.toloidp.security.SpecTokenExchangeAuthenticationProvider
import dev.usbharu.toloidp.security.TenantAuthorizationValidator
import dev.usbharu.toloidp.security.TenantAwareAuthorizationRequestConverter
import dev.usbharu.toloidp.security.ToloJwtCustomizer
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.security.provisioning.UserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import javax.sql.DataSource
import java.time.Clock
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import java.util.UUID

@Configuration
@EnableConfigurationProperties(IdpProperties::class)
class SecurityConfig {
    @Bean
    @Order(0)
    fun relationCacheSecurityFilterChain(
        http: HttpSecurity,
        properties: IdpProperties,
    ): SecurityFilterChain {
        http.securityMatcher("/internal/relation-cache/**")
            .authorizeHttpRequests {
                it.anyRequest().hasRole("RELATION_CACHE_ADMIN")
            }
            .x509 {
                it.authenticationUserDetailsService { token: PreAuthenticatedAuthenticationToken ->
                    val subject = token.name
                    val user = User.withUsername(subject).password("")
                    if (subject in properties.relation.cache.adminSubjects) {
                        user.roles("RELATION_CACHE_ADMIN")
                    } else {
                        user.roles("RELATION_CACHE_DENIED")
                    }
                    user.build()
                }
            }
            .csrf { it.disable() }
            .formLogin { it.disable() }
            .logout { it.disable() }
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            }
        return http.build()
    }

    @Bean
    @Order(1)
    fun disabledRevocationSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.securityMatcher("/oauth2/revoke")
            .authorizeHttpRequests {
                it.anyRequest().denyAll()
            }
            .csrf { it.disable() }
            .formLogin { it.disable() }
            .logout { it.disable() }
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.NOT_FOUND))
                it.accessDeniedHandler { _, response, _ ->
                    response.sendError(HttpStatus.NOT_FOUND.value())
                }
            }
        return http.build()
    }

    @Bean
    @Order(2)
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
        registeredClientRepository: RegisteredClientRepository,
        authorizationService: OAuth2AuthorizationService,
        authorizationConsentService: OAuth2AuthorizationConsentService,
        tokenGenerator: OAuth2TokenGenerator<OAuth2Token>,
        clientPolicyRepository: ClientPolicyRepository,
        resourceParser: ResourceParser,
        relationService: RelationService,
        scopePolicy: ScopePolicy,
        jtiDenylistRepository: JtiDenylistRepository,
        auditService: AuditService,
        clock: Clock,
        settings: AuthorizationServerSettings,
    ): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
        http.with(authorizationServerConfigurer) { authorizationServer ->
            authorizationServer
                .registeredClientRepository(registeredClientRepository)
                .authorizationService(authorizationService)
                .authorizationConsentService(authorizationConsentService)
                .authorizationServerSettings(settings)
                .tokenGenerator(tokenGenerator)
                .authorizationServerMetadataEndpoint { metadataEndpoint ->
                    metadataEndpoint.authorizationServerMetadataCustomizer { metadata ->
                        metadata.claims { claims ->
                            claims.remove(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT)
                            claims.remove(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED)
                        }
                        metadata.grantTypes {
                            it.clear()
                            it.add(AuthorizationGrantType.AUTHORIZATION_CODE.value)
                            it.add(AuthorizationGrantType.TOKEN_EXCHANGE.value)
                        }
                        metadata.tokenEndpointAuthenticationMethods {
                            it.clear()
                            it.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value)
                        }
                        metadata.tokenIntrospectionEndpointAuthenticationMethods {
                            it.clear()
                            it.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value)
                        }
                    }
                }
                .authorizationEndpoint { authorizationEndpoint ->
                authorizationEndpoint.authorizationRequestConverters { converters ->
                    converters.removeIf { it is OAuth2AuthorizationCodeRequestAuthenticationConverter }
                    converters.add(0, TenantAwareAuthorizationRequestConverter(resourceParser))
                }
                authorizationEndpoint.authenticationProviders { providers ->
                    providers.filterIsInstance<OAuth2AuthorizationCodeRequestAuthenticationProvider>()
                        .forEach {
                            it.setAuthenticationValidator(
                                TenantAuthorizationValidator(
                                    clientPolicyRepository,
                                    resourceParser,
                                    relationService,
                                    scopePolicy,
                                ),
                            )
                        }
                }
            }
                .tokenEndpoint { tokenEndpoint ->
                tokenEndpoint.authenticationProviders { providers ->
                    providers.removeIf { it is OAuth2TokenExchangeAuthenticationProvider }
                    providers.add(
                        SpecTokenExchangeAuthenticationProvider(
                            authorizationService,
                            tokenGenerator,
                            clientPolicyRepository,
                            resourceParser,
                            relationService,
                            scopePolicy,
                            jtiDenylistRepository,
                            auditService,
                            clock,
                        ),
                    )
                }
            }
        }

        http.securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .csrf { it.ignoringRequestMatchers(authorizationServerConfigurer.endpointsMatcher) }
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            }
            .formLogin { it.disable() }
        return http.build()
    }

    @Bean
    @Order(3)
    fun applicationSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests {
            it.requestMatchers("/actuator/health", "/api/login").permitAll()
                .anyRequest().authenticated()
        }
            .exceptionHandling {
                it.authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            }
            .formLogin { it.disable() }
            .logout { it.disable() }
            .csrf { it.disable() }
        return http.build()
    }

    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate): RegisteredClientRepository =
        JdbcRegisteredClientRepository(jdbcTemplate)

    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationService =
        JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)

    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationConsentService =
        JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)

    @Bean
    fun authorizationServerSettings(properties: IdpProperties): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().issuer(properties.issuer).build()

    @Bean
    fun userDetailsService(dataSource: DataSource): UserDetailsManager =
        JdbcUserDetailsManager(dataSource)

    @Bean
    fun passwordEncoder(): PasswordEncoder =
        PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun roleHierarchy(): RoleHierarchy =
        ScopePolicy.defaultRoleHierarchy()

    @Bean
    fun jwkSource(properties: IdpProperties): JWKSource<SecurityContext> {
        val rsaKey = configuredRsaKey(properties.jwk) ?: ephemeralRsaKey(properties.jwk)
        return ImmutableJWKSet(JWKSet(rsaKey))
    }

    private fun configuredRsaKey(properties: IdpProperties.Jwk): RSAKey? {
        val privateKeyPem = properties.privateKeyPem?.takeIf { it.isNotBlank() }
            ?: properties.privateKeyLocation?.let {
                if (!it.exists()) {
                    throw IllegalStateException("Configured tolo-idp.jwk.private-key-location does not exist: $it")
                }
                it.inputStream.bufferedReader().use { reader -> reader.readText() }
            }
            ?: return null
        val privateKey = parsePkcs8RsaPrivateKey(privateKeyPem)
        val publicKey = derivePublicKey(privateKey)
        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(properties.keyId?.takeIf { it.isNotBlank() } ?: stableKeyId(publicKey))
            .build()
    }

    private fun ephemeralRsaKey(properties: IdpProperties.Jwk): RSAKey {
        if (!properties.allowEphemeral) {
            throw IllegalStateException(
                "Configure tolo-idp.jwk.private-key-pem or tolo-idp.jwk.private-key-location, " +
                    "or explicitly set tolo-idp.jwk.allow-ephemeral=true for dev/test.",
            )
        }
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        return RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(properties.keyId?.takeIf { it.isNotBlank() } ?: UUID.randomUUID().toString())
            .build()
    }

    private fun parsePkcs8RsaPrivateKey(pem: String): RSAPrivateKey {
        val base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .lines()
            .joinToString("") { it.trim() }
        val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64))
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec) as RSAPrivateKey
    }

    private fun derivePublicKey(privateKey: RSAPrivateKey): RSAPublicKey {
        val crtKey = privateKey as? RSAPrivateCrtKey
            ?: throw IllegalArgumentException("RSA private key must include CRT parameters to derive a public key")
        val keySpec = RSAPublicKeySpec(crtKey.modulus, crtKey.publicExponent)
        return KeyFactory.getInstance("RSA").generatePublic(keySpec) as RSAPublicKey
    }

    private fun stableKeyId(publicKey: RSAPublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder =
        NimbusJwtEncoder(jwkSource)

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    @Bean
    fun tokenGenerator(
        jwtEncoder: JwtEncoder,
        jwtCustomizer: ToloJwtCustomizer,
    ): OAuth2TokenGenerator<OAuth2Token> {
        val jwtGenerator = JwtGenerator(jwtEncoder)
        jwtGenerator.setJwtCustomizer(jwtCustomizer)
        return DelegatingOAuth2TokenGenerator(jwtGenerator)
    }

    @Bean
    fun clock(): java.time.Clock = java.time.Clock.systemUTC()
}
