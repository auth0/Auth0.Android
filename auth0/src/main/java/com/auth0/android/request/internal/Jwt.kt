package com.auth0.android.request.internal

import android.util.Base64
import com.auth0.android.provider.TokenValidationException
import com.google.gson.reflect.TypeToken
import java.util.*


internal class Jwt(rawToken: String) {

    val parts: Array<String>
    private val decodedHeader: Map<String, Any>
    private val decodedPayload: Map<String, Any>

    // TODO: Convert fun to properties. Assign once on the init method

    // header
    fun getType(): String = decodedHeader["typ"] as String
    fun getAlgorithm(): String = decodedHeader["alg"] as String
    fun getKeyId(): String? = decodedHeader["kid"] as String?

    // payload
    fun getSubject(): String? = decodedPayload["sub"] as String?
    fun getIssuer(): String? = decodedPayload["iss"] as String?
    fun getNonce(): String? = decodedPayload["nonce"] as String?
    fun getIssuedAt(): Date? = (decodedPayload["iat"] as? Double)?.let { Date(it.toLong() * 1000) }
    fun getExpiresAt(): Date? = (decodedPayload["exp"] as? Double)?.let { Date(it.toLong() * 1000) }
    fun getAuthorizedParty(): String? = decodedPayload["azp"] as String?
    fun getAuthenticationTime(): Date? =
        (decodedPayload["auth_time"] as? Double)?.let { Date(it.toLong() * 1000) }

    fun getAudience(): List<String> {
        return when (val aud = decodedPayload["aud"]) {
            is String -> listOf(aud)
            is List<*> -> aud as List<String>
            else -> emptyList()
        }
    }

    init {
        parts = splitToken(rawToken)
        val jsonHeader = parts[0].decodeBase64()
        val jsonPayload = parts[1].decodeBase64()
        val mapAdapter = GsonProvider.gson.getAdapter(object : TypeToken<Map<String, Any>>() {})
        decodedHeader = mapAdapter.fromJson(jsonHeader)
        decodedPayload = mapAdapter.fromJson(jsonPayload)
    }

    private fun splitToken(token: String): Array<String> {
        var parts = token.split(".").toTypedArray()
        if (parts.size == 2 && token.endsWith(".")) {
            // Tokens with alg='none' have empty String as Signature.
            parts = arrayOf(parts[0], parts[1], "")
        }
        if (parts.size != 3) {
            throw TokenValidationException(
                String.format(
                    "The token was expected to have 3 parts, but got %s.",
                    parts.size
                )
            )
        }
        return parts
    }

    private fun String.decodeBase64(): String {
        val bytes: ByteArray =
            Base64.decode(this, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return String(bytes, Charsets.UTF_8)
    }

}