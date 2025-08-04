package com.auth0.android.dpop

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.auth0.android.request.getErrorBody
import okhttp3.Response
import org.json.JSONObject
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECPublicKey
import java.util.UUID


/**
 * Data class returning the value that needs to be added to the request for the `Authorization` and `DPoP` headers.
 * @param  authorizationHeader value for the `Authorization` header key
 * @param dpopProof value for the `DPoP header key . This will be generated only for DPoP requests
 */
public data class HeaderData(val authorizationHeader: String, val dpopProof: String?)


/**
 * Util class for securing requests with DPoP (Demonstrating Proof of Possession) as described in
 * [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
 */
public object DPoPProvider {

    private const val TAG = "DPoPManager"
    private const val NONCE_REQUIRED_ERROR = "use_dpop_nonce"
    private const val NONCE_HEADER = "dpop-nonce"
    public const val DPOP_HEADER: String = "DPoP"


    public const val MAX_RETRY_COUNT: Int = 1

    public var auth0Nonce: String? = null
        private set

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    @Volatile
    internal var keyStore = DPoPKeyStore()

    /**
     * This method constructs a DPoP proof JWT that includes the HTTP method, URL, and an optional access token and nonce.
     *
     * ```kotlin
     *
     *  try {
     *       DPoPProvider.generateProof("{url}", "POST")?.let {
     *            // Add to the URL request header
     *        }
     *     } catch (exception: DPoPException) {
     *          Log.e(TAG, "Error generating DPoP proof: ${exception.stackTraceToString()}")
     *    }
     *
     * ```
     *
     * @param httpUrl The URL of the HTTP request for which the DPoP proof is being generated.
     * @param httpMethod The HTTP method (e.g., "GET", "POST") of the request.
     * @param accessToken An optional access token to be included in the proof. If provided, it will be hashed and included in the payload.
     * @param nonce An optional nonce value to be included in the proof. This can be used to prevent replay attacks.
     * @throws DPoPException if there is an error generating the DPoP proof or accessing the key pair.
     */
    @Throws(DPoPException::class)
    @JvmStatic
    public fun generateProof(
        httpUrl: String,
        httpMethod: String,
        accessToken: String? = null,
        nonce: String? = null
    ): String? {
        if (!keyStore.hasKeyPair()) {
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
        val payloadJson = JSONObject().apply {
            put("jti", UUID.randomUUID().toString())
            put("htm", httpMethod.uppercase())
            put("htu", httpUrl)
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

    /**
     * Method to clear the DPoP key pair from the keystore. It must be called when the user logs out
     * to prevent reuse of the key pair in subsequent sessions.
     *
     * ```kotlin
     *
     *  try {
     *      DPoPProvider.clearKeyPair()
     *     } catch (exception: DPoPException) {
     *          Log.e(TAG,"Error clearing  the key pair from the keystore: ${exception.stackTraceToString()}")
     *     }
     *
     * ```
     * **Note** : It is the developer's responsibility to invoke this method to clear the keystore when logging out .
     * @throws DPoPException if there is an error deleting the key pair.
     */
    @Throws(DPoPException::class)
    @JvmStatic
    public fun clearKeyPair() {
        keyStore.deleteKeyPair()
    }

    /**
     * Method to get the public key in JWK format. This is used to generate the `jwk` field in the DPoP proof header.
     *
     * ```kotlin
     *
     *  try {
     *      val publicKeyJWK = DPoPProvider.getPublicKeyJWK()
     *      Log.d(TAG, "Public Key JWK: $publicKeyJWK")
     *     } catch (exception: DPoPException) {
     *          Log.e(TAG,"Error getting public key JWK: ${exception.stackTraceToString()}")
     *     }
     *
     * ```
     *
     * @return The public key in JWK format or null if the key pair is not present.
     * @throws DPoPException if there is an error accessing the key pair.
     */
    @Throws(DPoPException::class)
    @JvmStatic
    public fun getPublicKeyJWK(): String? {
        if (!keyStore.hasKeyPair()) {
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

    /**
     * Generates a new key pair for DPoP if it does not already exist. This should be called before making any requests that require a DPoP proof.
     *
     * ```kotlin
     *
     *  try {
     *      DPoPProvider.generateKeyPair(context)
     *     } catch (exception: DPoPException) {
     *          Log.e(TAG,"Error generating key pair: ${exception.stackTraceToString()}")
     *     }
     *
     * ```
     *
     * @param context The application context used to access the keystore.
     * @throws DPoPException if there is an error generating the key pair or accessing the keystore.
     */
    @Throws(DPoPException::class)
    @JvmStatic
    public fun generateKeyPair(context: Context) {
        if (keyStore.hasKeyPair()) {
            return
        }
        keyStore.generateKeyPair(context)
    }

    /**
     * Generates the header data for a request that requires DPoP proof of possession. The `Authorization` header value is created
     * using the access token and token type. The `DPoP` header value contains the generated DPoP proof.
     *
     * ```kotlin
     *
     *  try {
     *        val headerData = DPoPProvider.getHeaderData(
     *            "{POST}",
     *            "{request_url}",
     *            "{access_token}",
     *            "{DPoP}",
     *            "{nonce_value}"
     *            )
     *            addHeader("Authorization", headerData.authorizationHeader) //Adding to request header
     *            headerData.dpopProof?.let {
     *                 addHeader("DPoP", it)
     *            }
     *      } catch (exception: DPoPException) {
     *            Log.e(TAG, "Error generating DPoP proof: ${exception.stackTraceToString()}")
     *      }
     *
     * ```
     *
     * @param httpMethod Method type of the request
     * @param httpUrl Url of the request
     * @param accessToken Access token to be included in the `Authorization` header
     * @param tokenType Either `DPoP` or `Bearer`
     * @param nonce Optional nonce value to be used in the proof
     * @throws DPoPException if there is an error generating the DPoP proof or accessing the key pair
     */
    @Throws(DPoPException::class)
    @JvmStatic
    public fun getHeaderData(
        httpMethod: String,
        httpUrl: String,
        accessToken: String,
        tokenType: String,
        nonce: String? = null
    ): HeaderData {
        val token = "$tokenType $accessToken"
        if (!tokenType.equals("DPoP", ignoreCase = true)) return HeaderData(token, null)
        val proof = generateProof(httpUrl, httpMethod, accessToken, nonce)
        return HeaderData(token, proof)
    }

    /**
     * Checks if the given [Response] indicates that a nonce is required for DPoP requests.
     * This is typically used to determine if the request needs to be retried with a nonce.
     *
     * ```kotlin
     *
     *  if (DPoPProvider.isNonceRequiredError(response)) {
     *      // Handle nonce required error
     *  }
     *
     * ```
     *
     * @param response The HTTP response to check for nonce requirement.
     * @return True if the response indicates that a nonce is required, false otherwise.
     */
    @JvmStatic
    public fun isNonceRequiredError(response: Response): Boolean {
        return (response.code == 400 && response.getErrorBody().errorCode == NONCE_REQUIRED_ERROR) ||
                (response.code == 401 && isResourceServerNonceError(response))
    }

    /**
     * Stores the nonce value from the Okhttp3 [Response] headers.
     *
     * ```kotlin
     *
     *  try {
     *      DPoPProvider.storeNonce(response)
     *  } catch (exception: Exception) {
     *      Log.e(TAG, "Error storing nonce: ${exception.stackTraceToString()}")
     *  }
     *
     * ```
     *
     * @param response The HTTP response containing the nonce header.
     */
    @JvmStatic
    public fun storeNonce(response: Response) {
        auth0Nonce = response.headers[NONCE_HEADER]
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
        return Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
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
        if (r.size > 1 && r[0] == 0x00.toByte() && r[1].toInt() and 0x80 == 0x80) r =
            r.copyOfRange(1, r.size)
        if (s.size > 1 && s[0] == 0x00.toByte() && s[1].toInt() and 0x80 == 0x80) s =
            s.copyOfRange(1, s.size)

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
        if (len and 0x80 != 0) {
            val numBytes = len and 0x7F
            len = 0
            for (i in 0 until numBytes) {
                len = (len shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
            }
            bytesConsumed += numBytes
        }
        return Pair(len, bytesConsumed)
    }

    private fun isResourceServerNonceError(response: Response): Boolean {
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
}