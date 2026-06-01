package dev.usbharu.toloidp.resource

import dev.usbharu.toloidp.config.IdpProperties
import org.springframework.stereotype.Component
import java.net.URI

@Component
class ResourceParser(
    private val properties: IdpProperties,
) {
    private val idRegex = Regex("^[A-Za-z0-9_-]{1,64}$")

    fun tenantResource(tenantId: String): String {
        requireValidId(tenantId)
        val host = properties.resource.allowedHosts.first()
        return "https://$host/tenants/$tenantId"
    }

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
        if (!uri.isAbsolute || uri.scheme != "https" || uri.host !in properties.resource.allowedHosts) {
            throw ResourceValidationException("resource_not_allowed")
        }
        if (uri.rawQuery != null || uri.rawFragment != null || uri.rawUserInfo != null) {
            throw ResourceValidationException("resource_invalid_format")
        }
        return uri
    }

    private fun pathSegments(uri: URI): List<String> =
        uri.rawPath.split('/').filter { it.isNotEmpty() }
}

class ResourceValidationException(
    val reason: String,
) : RuntimeException(reason)
