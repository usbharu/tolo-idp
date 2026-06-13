package dev.usbharu.toloidp.resource

import dev.usbharu.toloidp.config.IdpProperties
import org.springframework.stereotype.Component
import java.net.URI

/**
 * IDP 仕様で定義した OAuth2 `resource` パラメータを解析・検証するコンポーネント。
 *
 * resource は許可済み host の絶対 HTTPS URI であり、tenant / event の path 形式に
 * 厳密に一致する必要がある。
 */
@Component
class ResourceParser(
    private val properties: IdpProperties,
) {
    private val idRegex = Regex("^[A-Za-z0-9_-]{1,64}$")

    /**
     * 検証済み tenant ID から canonical な tenant resource URI を組み立てる。
     */
    fun tenantResource(tenantId: String): String {
        requireValidId(tenantId)
        val host = properties.resource.allowedHosts.first()
        return "https://$host/tenants/$tenantId"
    }

    /**
     * tenant resource URI を解析し、URI に含まれる tenant ID を返す。
     */
    fun parseTenant(value: String): TenantResource {
        val uri = parseBase(value)
        val segments = pathSegments(uri)
        if (segments.size != 2 || segments[0] != "tenants") {
            throw ResourceValidationException("resource_invalid_format")
        }
        val tenantId = segments[1]
        requireValidId(tenantId)
        return TenantResource(value, tenantId)
    }

    /**
     * event resource URI を解析し、URI に含まれる tenant ID と event ID を返す。
     */
    fun parseEvent(value: String): EventResource {
        val uri = parseBase(value)
        val segments = pathSegments(uri)
        if (segments.size != 4 || segments[0] != "tenants" || segments[2] != "events") {
            throw ResourceValidationException("resource_invalid_format")
        }
        val tenantId = segments[1]
        val eventId = segments[3]
        requireValidId(tenantId)
        requireValidId(eventId)
        return EventResource(value, tenantId, eventId)
    }

    /**
     * ID が `spec.md` の ASCII ID 形式に一致することを要求する。
     */
    fun requireValidId(id: String) {
        if (!idRegex.matches(id)) {
            throw ResourceValidationException("resource_invalid_format")
        }
    }

    private fun parseBase(value: String): URI {
        val uri = try {
            URI(value)
        } catch (ex: IllegalArgumentException) {
            throw ResourceValidationException("resource_invalid_format")
        }
        if (!uri.isAbsolute || uri.scheme != "https" || uri.host !in properties.resource.allowedHosts || uri.port != -1) {
            throw ResourceValidationException("resource_not_allowed")
        }
        if (uri.rawQuery != null || uri.rawFragment != null || uri.rawUserInfo != null) {
            throw ResourceValidationException("resource_invalid_format")
        }
        return uri
    }

    private fun pathSegments(uri: URI): List<String> {
        val rawPath = uri.rawPath
        if (!rawPath.startsWith("/") || rawPath.contains("//") || rawPath.endsWith("/")) {
            throw ResourceValidationException("resource_invalid_format")
        }
        return rawPath.removePrefix("/").split('/')
    }
}

class ResourceValidationException(
    val reason: String,
) : RuntimeException(reason)
