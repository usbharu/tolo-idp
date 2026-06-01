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
import org.springframework.jdbc.core.simple.JdbcClient
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import javax.sql.DataSource
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
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
        jdbcClient: JdbcClient,
        auditService: AuditService,
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
                            jdbcClient,
                            auditService,
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
    @Order(2)
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
    fun userDetailsService(dataSource: DataSource): UserDetailsService =
        JdbcUserDetailsManager(dataSource)

    @Bean
    fun passwordEncoder(): PasswordEncoder =
        PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        return ImmutableJWKSet(JWKSet(rsaKey))
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
