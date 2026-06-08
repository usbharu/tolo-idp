package dev.usbharu.toloidp.ratelimit

import java.time.Duration

data class RateLimitIdentity(
    val ip: String,
    val userId: String?,
)

enum class RateLimitDimension {
    IP_USER,
    USER,
    IP,
}

data class RateLimitDecision(
    val allowed: Boolean,
    val rejectedDimension: RateLimitDimension? = null,
    val retryAfter: Duration? = null,
)

interface RateLimitService {
    fun consume(identity: RateLimitIdentity): RateLimitDecision
}

class RateLimitUnavailableException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

