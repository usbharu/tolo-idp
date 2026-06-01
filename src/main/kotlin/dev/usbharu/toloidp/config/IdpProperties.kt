package dev.usbharu.toloidp.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "tolo-idp")
data class IdpProperties(
    val issuer: String = "http://localhost:8080",
    val resource: Resource = Resource(),
    val relation: Relation = Relation(),
    val token: Token = Token(),
    val seed: Seed = Seed(),
) {
    data class Resource(
        val allowedHosts: Set<String> = setOf("api.example.com"),
    )

    data class Relation(
        val baseUrl: String = "http://localhost:8081",
        val connectTimeout: Duration = Duration.ofSeconds(2),
        val readTimeout: Duration = Duration.ofSeconds(3),
        val cache: Cache = Cache(),
    ) {
        data class Cache(
            val ttl: Duration = Duration.ofMinutes(5),
            val adminSubjects: Set<String> = emptySet(),
        )
    }

    data class Token(
        val tenantAccessTtl: Duration = Duration.ofMinutes(15),
        val eventAccessTtl: Duration = Duration.ofMinutes(10),
    )

    data class Seed(
        val enabled: Boolean = true,
        val clientSecret: String = "secret",
        val userPassword: String = "password",
    )
}
