package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.resource.ResourceValidationException
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.scope.UnknownRelationRoleException
import org.springframework.http.HttpStatus
import org.springframework.http.client.JdkClientHttpRequestFactory
import org.springframework.stereotype.Service
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException
import java.net.http.HttpClient

@Service
class HttpRelationService(
    properties: IdpProperties,
    private val resourceParser: ResourceParser,
) : RelationService {
    private val restClient: RestClient = RestClient.builder()
        .baseUrl(properties.relation.baseUrl)
        .requestFactory(
            JdkClientHttpRequestFactory(
                HttpClient.newBuilder()
                    .connectTimeout(properties.relation.connectTimeout)
                    .build(),
            ),
        )
        .build()

    override fun getMembership(tenantId: String, userId: String): TenantMembership {
        resourceParser.requireValidId(tenantId)
        val response = getOrNull<MembershipResponse>("/tenants/{tenantId}/users/{userId}", tenantId, userId)
            ?: throw RelationLookupException("tenant_not_found")
        if (response.tenant.id != tenantId || response.user.id != userId) {
            throw RelationLookupException("relation_response_invalid")
        }
        val roleValue = response.tenant.role ?: throw RelationLookupException("user_not_tenant_member")
        val tenantRole = parseRole(roleValue)
        val events = try {
            response.events.map {
                resourceParser.requireValidId(it.id)
                EventMembership(it.id, parseRole(it.role))
            }
        } catch (ex: ResourceValidationException) {
            throw RelationLookupException("relation_response_invalid")
        }
        return TenantMembership(tenantId, tenantRole, events)
    }

    private inline fun <reified T : Any> getOrNull(path: String, vararg variables: String): T? {
        return try {
            restClient.get()
                .uri(path, *variables)
                .retrieve()
                .onStatus({ it == HttpStatus.NOT_FOUND }) { _, _ -> throw RelationLookupException("tenant_not_found") }
                .body(T::class.java)
        } catch (ex: RelationLookupException) {
            throw ex
        } catch (ex: RestClientException) {
            throw RelationLookupException("relation_lookup_failed")
        } catch (ex: RuntimeException) {
            throw RelationLookupException("relation_response_invalid")
        }
    }

    private fun parseRole(value: String): RelationRole {
        return try {
            RelationRole.fromExternal(value)
        } catch (ex: UnknownRelationRoleException) {
            throw RelationLookupException("relation_role_unknown")
        }
    }

    data class MembershipResponse(
        val tenant: TenantNode = TenantNode(),
        val user: UserNode = UserNode(),
        val events: List<EventNode> = emptyList(),
    )

    data class TenantNode(
        val id: String = "",
        val role: String? = null,
    )

    data class UserNode(
        val id: String = "",
    )

    data class EventNode(
        val id: String = "",
        val role: String = "",
    )
}
