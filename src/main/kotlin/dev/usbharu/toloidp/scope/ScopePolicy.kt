package dev.usbharu.toloidp.scope

import org.springframework.stereotype.Component

enum class RelationRole {
    OWNER,
    ADMIN,
    STAFF;

    companion object {
        fun fromExternal(value: String?): RelationRole {
            return when (value) {
                "owner" -> OWNER
                "staff" -> STAFF
                else -> throw UnknownRelationRoleException()
            }
        }
    }
}

class UnknownRelationRoleException : RuntimeException("relation_role_unknown")

@Component
class ScopePolicy {
    private val ownerScopes = setOf("tenant.read", "tenant.write", "events.read", "events.write")
    private val staffScopes = setOf("tenant.read", "events.read")

    fun allowedScopes(role: RelationRole): Set<String> =
        when (role) {
            RelationRole.OWNER, RelationRole.ADMIN -> ownerScopes
            RelationRole.STAFF -> staffScopes
        }

    fun requireAllowed(requested: Set<String>, allowed: Set<String>, reason: String) {
        if (!allowed.containsAll(requested)) {
            throw ScopeNotAllowedException(reason)
        }
    }
}

class ScopeNotAllowedException(
    val reason: String,
) : RuntimeException(reason)
