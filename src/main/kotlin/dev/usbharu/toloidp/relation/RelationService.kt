package dev.usbharu.toloidp.relation

interface RelationService {
    fun getMembership(tenantId: String, userId: String): TenantMembership
}
