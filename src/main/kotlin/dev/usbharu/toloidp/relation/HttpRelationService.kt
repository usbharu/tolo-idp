package dev.usbharu.toloidp.relation

import dev.usbharu.toloidp.config.IdpProperties
import dev.usbharu.toloidp.resource.ResourceParser
import dev.usbharu.toloidp.resource.ResourceValidationException
import dev.usbharu.toloidp.scope.RelationRole
import dev.usbharu.toloidp.scope.UnknownRelationRoleException
import org.slf4j.LoggerFactory
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
        log.trace("getMembership started: tenantId={}, userId={}", tenantId, userId)
        resourceParser.requireValidId(tenantId)
        val response = getOrNull<MembershipResponse>("/tenants/{tenantId}/users/{userId}", tenantId, userId)
            ?: throw RelationLookupException("tenant_not_found")
        if (response.tenant.id != tenantId || response.user.id != userId) {
            log.warn(
                "Relation service returned mismatched membership: tenantId={}, userId={}, responseTenantId={}, responseUserId={}",
                tenantId,
                userId,
                response.tenant.id,
                response.user.id,
            )
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
            log.warn("Relation service returned invalid event id: tenantId={}, userId={}", tenantId, userId, ex)
            throw RelationLookupException("relation_response_invalid")
        }
        log.debug(
            "Relation membership lookup completed: tenantId={}, userId={}, tenantRole={}, eventCount={}",
            tenantId,
            userId,
            tenantRole,
            events.size,
        )
        log.trace("getMembership completed: tenantId={}, userId={}, eventCount={}", tenantId, userId, events.size)
        return TenantMembership(tenantId, tenantRole, events)
    }

    private inline fun <reified T : Any> getOrNull(path: String, vararg variables: String): T? {
        return try {
            log.debug("Relation API request started: path={}, variableCount={}", path, variables.size)
            restClient.get()
                .uri(path, *variables)
                .retrieve()
                .onStatus({ it == HttpStatus.NOT_FOUND }) { _, _ -> throw RelationLookupException("tenant_not_found") }
                .body(T::class.java)
                .also { log.debug("Relation API request completed: path={}, responsePresent={}", path, it != null) }
        } catch (ex: RelationLookupException) {
            log.debug("Relation API request returned a known lookup failure: path={}, reason={}", path, ex.reason)
            throw ex
        } catch (ex: RestClientException) {
            log.warn("Relation API request failed: path={}", path, ex)
            throw RelationLookupException("relation_lookup_failed")
        } catch (ex: RuntimeException) {
            log.warn("Relation API response handling failed: path={}", path, ex)
            throw RelationLookupException("relation_response_invalid")
        }
    }

    private fun parseRole(value: String): RelationRole {
        return try {
            RelationRole.fromExternal(value)
        } catch (ex: UnknownRelationRoleException) {
            log.warn("Relation service returned unknown role: role={}", value, ex)
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

    companion object {
        private val log = LoggerFactory.getLogger(HttpRelationService::class.java)
    }
}
