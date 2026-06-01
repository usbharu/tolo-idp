package dev.usbharu.toloidp.resource

import dev.usbharu.toloidp.config.IdpProperties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ResourceParserTests {
    private val parser = ResourceParser(
        IdpProperties(resource = IdpProperties.Resource(allowedHosts = setOf("api.example.com"))),
    )

    @Test
    fun parsesTenantResource() {
        val resource = parser.parseTenant("https://api.example.com/tenants/tenant-a")
        assertEquals("tenant-a", resource.tenantId)
    }

    @Test
    fun parsesEventResource() {
        val resource = parser.parseEvent("https://api.example.com/tenants/tenant-a/events/event-1")
        assertEquals("tenant-a", resource.tenantId)
        assertEquals("event-1", resource.eventId)
    }

    @Test
    fun rejectsInvalidIdWithoutTrimming() {
        assertFailsWith<ResourceValidationException> {
            parser.parseTenant("https://api.example.com/tenants/%20tenant-a")
        }
    }

    @Test
    fun rejectsHttpScheme() {
        assertFailsWith<ResourceValidationException> {
            parser.parseEvent("http://api.example.com/tenants/tenant-a/events/event-1")
        }
    }
}
