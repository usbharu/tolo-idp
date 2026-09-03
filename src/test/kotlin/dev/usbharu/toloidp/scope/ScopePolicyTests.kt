package dev.usbharu.toloidp.scope

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl

class ScopePolicyTests {
    private val policy = ScopePolicy()

    @Test
    fun ownerAllowsAllTemporaryScopes() {
        val allowed = policy.allowedScopes(RelationRole.OWNER)
        assertTrue(allowed.containsAll(setOf("tenant.read", "tenant.write", "events.read", "events.write")))
    }

    @Test
    fun adminAllowsAllTemporaryScopes() {
        val allowed = policy.allowedScopes(RelationRole.ADMIN)
        assertTrue(allowed.containsAll(setOf("tenant.read", "tenant.write", "events.read", "events.write")))
    }

    @Test
    fun staffAllowsOnlyReadScopesFromRoleHierarchy() {
        assertEquals(setOf("tenant.read", "events.read"), policy.allowedScopes(RelationRole.STAFF))
    }

    @Test
    fun staffDoesNotAllowWriteScopes() {
        assertFailsWith<ScopeNotAllowedException> {
            policy.requireAllowed(setOf("events.write"), policy.allowedScopes(RelationRole.STAFF), "scope_not_allowed_for_role")
        }
    }

    @Test
    fun identityScopeIsNotSubjectToRoleCheck() {
        policy.requireAllowedForRole(setOf("openid", "tenant.read"), RelationRole.STAFF, "scope_not_allowed_for_role")
        policy.requireAllowedForRole(setOf("openid"), RelationRole.STAFF, "scope_not_allowed_for_role")
    }

    @Test
    fun identityScopeDoesNotBypassRoleCheckForOtherScopes() {
        val exception = assertFailsWith<ScopeNotAllowedException> {
            policy.requireAllowedForRole(setOf("openid", "tenant.write"), RelationRole.STAFF, "scope_not_allowed_for_role")
        }
        assertEquals("scope_not_allowed_for_role", exception.reason)
    }

    @Test
    fun identityScopeIsNotGrantedByRoleHierarchy() {
        assertFalse(policy.allowedScopes(RelationRole.OWNER).contains("openid"))
        assertFailsWith<ScopeNotAllowedException> {
            policy.requireAllowed(setOf("openid"), policy.allowedScopes(RelationRole.OWNER), "scope_not_allowed_for_role")
        }
    }

    @Test
    fun usesInjectedRoleHierarchyForScopeResolution() {
        val customPolicy = ScopePolicy(
            RoleHierarchyImpl.fromHierarchy(
                """
                ROLE_STAFF > SCOPE_events.read
                """.trimIndent(),
            ),
        )

        assertEquals(setOf("events.read"), customPolicy.allowedScopes(RelationRole.STAFF))
    }

    @Test
    fun unknownExternalRoleFails() {
        assertFailsWith<UnknownRelationRoleException> {
            RelationRole.fromExternal("admin")
        }
    }
}
