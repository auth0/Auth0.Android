package com.auth0.android.dpop

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.annotation.VisibleForTesting
import okhttp3.Response
import org.json.JSONObject
import java.math.BigInteger
import java.net.URISyntaxException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECPublicKey
import java.util.UUID


/**
 * Util class for DPoP operations
 */
internal object DPoPUtil {

    private const val TAG = "DPoPUtil"

    internal const val NONCE_REQUIRED_ERROR = "use_dpop_nonce"
    internal const val MAX_RETRY_COUNT: Int = 1
    internal const val DPOP_HEADER: String = "DPoP"


    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    @Volatile
    internal var keyStore = DPoPKeyStore()


    @Throws(DPoPException::class)
    @JvmStatic
    internal fun generateProof(
        httpUrl: String,
        httpMethod: String,
        accessToken: String? = null,
        nonce: String? = null
    ): String? {
        if (!hasKeyPair()) {
            Log.d(TAG, "generateProof: Key pair is not present to generate the proof")
            return null
        }

        val keyPair = keyStore.getKeyPair()
        keyPair ?: run {
            Log.e(TAG, "generateProof: Key pair is null")
            return null
        }
        val (privateKey, publicKey) = keyPair

        // 1. Construct the header
        val headerJson = JSONObject().apply {
            put("typ", "dpop+jwt")
            put("alg", "ES256")
            put("jwk", createJWK(publicKey as ECPublicKey))
        }
        val headerEncoded = encodeBase64Url(headerJson.toString().toByteArray(Charsets.UTF_8))

        //2. Construct the Payload
        val cleanedUrl = cleanUrl(httpUrl)
        val payloadJson = JSONObject().apply {
            put("jti", UUID.randomUUID().toString())
            put("htm", httpMethod.uppercase())
            put("htu", cleanedUrl)
            put("iat", System.currentTimeMillis() / 1000)

            accessToken?.let {
                put("ath", createSHA256Hash(it))
            }
            nonce?.let {
                put("nonce", it)
            }
        }
        val payloadEncoded = encodeBase64Url(payloadJson.toString().toByteArray(Charsets.UTF_8))

        val signatureInput = "$headerEncoded.$payloadEncoded".toByteArray(Charsets.UTF_8)

        //4. Sign the data
        val signature = signData(signatureInput, privateKey)
        return "$headerEncoded.$payloadEncoded.${signature}"
    }


    @Throws(DPoPException::class)
    @JvmStatic
    internal fun getPublicKeyJWK(): String? {
        if (!hasKeyPair()) {
            Log.e(TAG, "getPublicKeyJWK: Key pair is not present to generate JWK")
            return null
        }

        val publicKey = keyStore.getKeyPair()?.second
        publicKey ?: return null
        if (publicKey !is ECPublicKey) {
            Log.e(TAG, "Key is not a ECPublicKey: ${publicKey.javaClass.name}")
            return null
        }
        val jwkJson = createJWK(publicKey)
        return createSHA256Hash(jwkJson.toString())
    }


    @Throws(DPoPException::class)
    @JvmStatic
    internal fun generateKeyPair(context: Context) {
        if (hasKeyPair()) {
            return
        }
        keyStore.generateKeyPair(context)
    }

    @Throws(DPoPException::class)
    @JvmStatic
    internal fun hasKeyPair(): Boolean {
        return keyStore.hasKeyPair()
    }

    @Throws(DPoPException::class)
    @JvmStatic
    internal fun clearKeyPair() {
        keyStore.deleteKeyPair()
    }

    internal fun isResourceServerNonceError(response: Response): Boolean {
        val header = response.headers["WWW-Authenticate"]
        header ?: return false
        val headerMap = header.split(", ")
            .map { it.split("=", limit = 2) }
            .associate {
                val key = it[0].trim()
                val value = it.getOrNull(1)?.trim()?.removeSurrounding("\"")
                key to (value ?: "")
            }
        return headerMap["DPoP error"] == NONCE_REQUIRED_ERROR
    }

    private fun createJWK(publicKey: ECPublicKey): JSONObject {
        val point = publicKey.w

        val x = point.affineX
        val y = point.affineY

        val xBytes = padTo32Bytes(x)
        val yBytes = padTo32Bytes(y)
        return JSONObject().apply {
            put("crv", "P-256")
            put("kty", "EC")
            put("x", encodeBase64Url(xBytes))
            put("y", encodeBase64Url(yBytes))
        }
    }

    private fun createSHA256Hash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return encodeBase64Url(hash)
    }

    private fun padTo32Bytes(coordinate: BigInteger): ByteArray {
        var bytes = coordinate.toByteArray()
        if (bytes.size > 1 && bytes[0] == 0x00.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        if (bytes.size < 32) {
            val paddedBytes = ByteArray(32)
            System.arraycopy(bytes, 0, paddedBytes, 32 - bytes.size, bytes.size)
            return paddedBytes
        }
        return bytes
    }

    private fun encodeBase64Url(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun signData(data: ByteArray, privateKey: PrivateKey): String? {
        try {
            val signatureBytes = Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(data)
                sign()
            }
            return encodeBase64Url(convertDerToRawSignature(signatureBytes))
        } catch (e: Exception) {
            Log.e(TAG, "Error signing data: ${e.stackTraceToString()}")
            throw DPoPException(DPoPException.Code.SIGNING_ERROR, e)
        }
    }

    private fun convertDerToRawSignature(derSignature: ByteArray): ByteArray {
        // DER format: SEQUENCE (0x30) + length + INTEGER (0x02) + length + R + INTEGER (0x02) + length + S
        var offset = 0
        if (derSignature[offset++] != 0x30.toByte()) throw SignatureException("Invalid DER signature: Expected SEQUENCE")
        val length = decodeLength(derSignature, offset).also { offset += it.second }.first
        if (length + offset != derSignature.size) throw SignatureException("Invalid DER signature: Length mismatch")

        if (derSignature[offset++] != 0x02.toByte()) throw SignatureException("Invalid DER signature: Expected INTEGER for R")
        val rLength = decodeLength(derSignature, offset).also { offset += it.second }.first
        var r = derSignature.copyOfRange(offset, offset + rLength)
        offset += rLength

        if (derSignature[offset++] != 0x02.toByte()) throw SignatureException("Invalid DER signature: Expected INTEGER for S")
        val sLength = decodeLength(derSignature, offset).also { offset += it.second }.first
        var s = derSignature.copyOfRange(offset, offset + sLength)
        offset += sLength

        // Remove leading zero if present
        if (r.size > 1 && r[0] == 0x00.toByte() && (r[1].toInt() and 0x80) == 0x80)
            r = r.copyOfRange(1, r.size)
        if (s.size > 1 && s[0] == 0x00.toByte() && (s[1].toInt() and 0x80) == 0x80)
            s = s.copyOfRange(1, s.size)

        // Pad with leading zeros to 32 bytes for P-256
        val rawR = ByteArray(32)
        System.arraycopy(r, 0, rawR, 32 - r.size, r.size)
        val rawS = ByteArray(32)
        System.arraycopy(s, 0, rawS, 32 - s.size, s.size)

        return rawR + rawS
    }

    private fun decodeLength(data: ByteArray, offset: Int): Pair<Int, Int> {
        var len = data[offset].toInt() and 0xFF
        var bytesConsumed = 1
        if ( (len and 0x80) != 0) {
            val numBytes = len and 0x7F
            len = 0
            for (i in 0 until numBytes) {
                len = (len shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
            }
            bytesConsumed += numBytes
        }
        return Pair(len, bytesConsumed)
    }

    private fun cleanUrl(url: String): String {
        return try {
            val uri = java.net.URI(url)
            val cleanedUri = java.net.URI(
                uri.scheme,
                uri.userInfo,
                uri.host,
                uri.port,
                uri.path,
                null, // Remove query
                null  // Remove fragment
            )
            cleanedUri.toString()
        } catch (e: URISyntaxException) {
            Log.d(TAG, "Failed to parse URL", e)
            throw  DPoPException.MALFORMED_URL
        }
    }

}