package com.auth0.android.request.internal

import android.util.Base64
import com.google.gson.reflect.TypeToken
import java.util.*


/**
 * Internal class meant to decode the given token of type JWT and provide access to its claims.
 */
internal class Jwt(rawToken: String) {

    val decodedHeader: Map<String, Any>
    val decodedPayload: Map<String, Any>
    val parts: Array<String>

    // header
    val algorithm: String
    val keyId: String?

    // payload
    val subject: String?
    val issuer: String?
    val nonce: String?
    val organizationId: String?
    val organizationName: String?
    val issuedAt: Date?
    val expiresAt: Date?
    val authorizedParty: String?
    val authenticationTime: Date?
    val audience: List<String>

    /**
     * The IPSIE `session_expiry` claim: an absolute session-expiry ceiling in **Unix seconds**
     * asserted by the upstream identity provider. Null when the connection does not emit the claim
     * or the value is not a plausible Unix-seconds timestamp (see [MAX_PLAUSIBLE_SESSION_EXPIRY]),
     * both of which MUST be treated as "no ceiling".
     */
    val sessionExpiry: Long?

    init {
        parts = splitToken(rawToken)
        val jsonHeader = decodeBase64(parts[0])
        val jsonPayload = decodeBase64(parts[1])
        val mapAdapter = GsonProvider.gson.getAdapter(object : TypeToken<Map<String, Any>>() {})
        decodedHeader = mapAdapter.fromJson(jsonHeader)
        decodedPayload = mapAdapter.fromJson(jsonPayload)

        // header claims
        algorithm = decodedHeader["alg"] as String
        keyId = decodedHeader["kid"] as String?

        // payload claims
        subject = decodedPayload["sub"] as String?
        issuer = decodedPayload["iss"] as String?
        nonce = decodedPayload["nonce"] as String?
        organizationId = decodedPayload["org_id"] as String?
        organizationName = decodedPayload["org_name"] as String?
        issuedAt = (decodedPayload["iat"] as? Double)?.let { Date(it.toLong() * 1000) }
        expiresAt = (decodedPayload["exp"] as? Double)?.let { Date(it.toLong() * 1000) }
        authorizedParty = decodedPayload["azp"] as String?
        authenticationTime =
            (decodedPayload["auth_time"] as? Double)?.let { Date(it.toLong() * 1000) }
        // `session_expiry` is customer-authored and expected in Unix *seconds*. A value mistakenly
        // emitted in milliseconds would parse as a timestamp ~50,000 years out and silently disable
        // the ceiling (fail-open), so reject implausibly large values and treat them as "no ceiling".
        // `as? Number` (not `as? Double`) so a JSON value deserialized as a Long is not dropped.
        sessionExpiry = (decodedPayload["session_expiry"] as? Number)?.toLong()
            ?.takeIf { it < MAX_PLAUSIBLE_SESSION_EXPIRY }
        audience = when (val aud = decodedPayload["aud"]) {
            is String -> listOf(aud)
            is List<*> -> aud as List<String>
            else -> emptyList()
        }
    }

    companion object {
        /**
         * Upper bound (exclusive) for a plausible `session_expiry` in Unix seconds: 10,000,000,000
         * (year ~2286). A value at or above this is almost certainly milliseconds and is treated as
         * "no ceiling" rather than a date tens of thousands of years out.
         */
        private const val MAX_PLAUSIBLE_SESSION_EXPIRY = 10_000_000_000L

        fun splitToken(token: String): Array<String> {
            var parts = token.split(".").toTypedArray()
            if (parts.size == 2 && token.endsWith(".")) {
                // Tokens with alg='none' have empty String as Signature.
                parts = arrayOf(parts[0], parts[1], "")
            }
            if (parts.size != 3) {
                throw IllegalArgumentException(
                    String.format(
                        "The token was expected to have 3 parts, but got %s.",
                        parts.size
                    )
                )
            }
            return parts
        }

        fun decodeBase64(encoded: String): String {
            val bytes: ByteArray =
                Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            return String(bytes, Charsets.UTF_8)
        }
    }

}