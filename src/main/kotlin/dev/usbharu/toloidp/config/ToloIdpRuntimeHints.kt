package dev.usbharu.toloidp.config

import dev.usbharu.toloidp.audit.TokenAuditEvent
import dev.usbharu.toloidp.logging.KeyValueLoggingEventEnhancer
import org.springframework.aot.hint.ExecutableMode
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.registerType
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Duration

class ToloIdpRuntimeHints : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
        val reflection = hints.reflection()
        reflection
            .registerConstructor(
                KeyValueLoggingEventEnhancer::class.java.getDeclaredConstructor(),
                ExecutableMode.INVOKE,
            )
        reflection.registerType<OAuth2TokenFormat>(
            MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
        )
        reflection.registerType<SignatureAlgorithm>()
        reflection.registerType<Duration>()
        reflection.registerType<TokenAuditEvent>(
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
            MemberCategory.DECLARED_FIELDS,
        )

        val resources = hints.resources()
        resources.registerPattern("db/migration/**")
        resources.registerPattern("db/postgresql")
        resources.registerPattern("db/postgresql/**")
    }
}
