package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.scope.RelationRole

data class TenantMembership(
    val tenantId: String,
    val tenantRole: RelationRole,
    val events: List<EventMembership>,
)

data class EventMembership(
    val eventId: String,
    val role: RelationRole,
)

class RelationLookupException(
    val reason: String,
) : RuntimeException(reason)
