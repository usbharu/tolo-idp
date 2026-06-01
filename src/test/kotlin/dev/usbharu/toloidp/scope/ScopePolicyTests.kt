package dev.usbharu.toloidp.scope

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ScopePolicyTests {
    private val policy = ScopePolicy()

    @Test
    fun ownerAllowsAllTemporaryScopes() {
        val allowed = policy.allowedScopes(RelationRole.OWNER)
        assertTrue(allowed.containsAll(setOf("tenant.read", "tenant.write", "events.read", "events.write")))
    }

    @Test
    fun staffDoesNotAllowWriteScopes() {
        assertFailsWith<ScopeNotAllowedException> {
            policy.requireAllowed(setOf("events.write"), policy.allowedScopes(RelationRole.STAFF), "scope_not_allowed_for_role")
        }
    }

    @Test
    fun unknownExternalRoleFails() {
        assertFailsWith<UnknownRelationRoleException> {
            RelationRole.fromExternal("admin")
        }
    }
}
