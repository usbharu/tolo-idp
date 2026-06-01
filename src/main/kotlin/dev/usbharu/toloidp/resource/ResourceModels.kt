package dev.usbharu.toloidp.resource

sealed interface ParsedResource {
    val value: String
    val tenantId: String
}

data class TenantResource(
    override val value: String,
    override val tenantId: String,
) : ParsedResource

data class EventResource(
    override val value: String,
    override val tenantId: String,
    val eventId: String,
) : ParsedResource
