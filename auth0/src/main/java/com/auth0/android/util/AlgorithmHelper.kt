package com.auth0.android.util

import android.util.Base64
import android.util.Log
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom

/**
 * Generates the PKCE (RFC 7636) code verifier and its S256 code challenge. Shared by the web-auth and
 * embedded flows.
 */
internal open class AlgorithmHelper {

    open fun getASCIIBytes(value: String): ByteArray = value.toByteArray(StandardCharsets.US_ASCII)

    /**
     * @throws IllegalStateException when the SHA-256 algorithm is not available.
     */
    open fun getSHA256(input: ByteArray): ByteArray {
        try {
            val md = MessageDigest.getInstance(SHA_256)
            md.update(input, 0, input.size)
            return md.digest()
        } catch (e: NoSuchAlgorithmException) {
            Log.e(TAG, "Failed to get SHA-256 signature", e)
            throw IllegalStateException("Failed to get SHA-256 signature", e)
        }
    }

    /** A random, base64url-encoded code verifier made of 32 random bytes. */
    open fun generateCodeVerifier(): String {
        val code = ByteArray(32)
        SecureRandom().nextBytes(code)
        return encode(code)
    }

    /** The S256 code challenge for [codeVerifier]: base64url(SHA-256(ASCII(codeVerifier))). */
    open fun generateCodeChallenge(codeVerifier: String): String =
        encode(getSHA256(getASCIIBytes(codeVerifier)))

    private fun encode(source: ByteArray): String =
        Base64.encodeToString(source, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private companion object {
        private val TAG = AlgorithmHelper::class.java.simpleName
        private const val SHA_256 = "SHA-256"
    }
}
