package com.auth0.android.dpop;

import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.util.UUID

public class DPoPProvider {

    private val keyStoreManager = KeyStoreManager()

    @RequiresApi(Build.VERSION_CODES.M)
    public fun generateDpopProofJwt(
        httpMethod: String,
        httpUrl: String,
        nonce: String? = null,
        accessToken: String? = null
    ): String? {
        val keyPair = keyStoreManager.getEs256KeyPair()
        if (keyPair == null) {
            println("Key pair not found to generate DPoP proof.")
            return null
        }

        val privateKey = keyPair.first
        val publicKey = keyPair.second

        try {
            // 1. Construct the Header
            val headerJson = JSONObject().apply {
                put("typ", "dpop+jwt")
                put("alg", "ES256") // Matches the P-256 curve
                put("jwk", createJwkFromPublicKey(publicKey))
            }
            val header = encodeBase64Url(headerJson.toString().toByteArray(Charsets.UTF_8))

            // 2. Construct the Payload
            val payloadJson = JSONObject().apply {
                put("jti", UUID.randomUUID().toString()) // Unique JWT ID
                put("htm", httpMethod.uppercase())
                put("htu", httpUrl)
                put("iat", System.currentTimeMillis() / 1000) // Issued At


                accessToken?.let {
                    val sha256Digest = MessageDigest.getInstance("SHA-256")
                    val athBytes = sha256Digest.digest(it.toByteArray(Charsets.US_ASCII))
                    put("ath", encodeBase64Url(athBytes))
                }
                nonce?.let {
                    put("nonce", it)
                }
            }
            val payload = encodeBase64Url(payloadJson.toString().toByteArray(Charsets.UTF_8))

            // 3. Create the Signing Input
            val signingInput = "$header.$payload".toByteArray(Charsets.UTF_8)

            // 4. Sign the JWT
            val signatureBytes = signData(signingInput, privateKey)
            if (signatureBytes == null) {
                println("Failed to sign DPoP proof JWT.")
                return null
            }

            // Convert raw ECDSA signature (R and S components) to DER encoding if needed,
            // but JWS ES256 expects raw R and S concatenated (often 64 bytes for P-256).
            // Android's Signature.sign() for ECDSA typically returns ASN.1 DER-encoded signature.
            // We need to convert it to the raw R and S concatenation expected by JWS.
            val rawSignature = convertDerToRawSignature(signatureBytes)

            val signature = encodeBase64Url(rawSignature)

            return "$header.$payload.$signature"
        } catch (e: Exception) {
            println("Error generating DPoP proof JWT: ${e.message}")
            e.printStackTrace()
        }
        return null
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

        // Remove leading zero if present (ASN.1 integer encoding for positive numbers)
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
        if (len and 0x80 != 0) { // Long form
            val numBytes = len and 0x7F
            len = 0
            for (i in 0 until numBytes) {
                len = (len shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
            }
            bytesConsumed += numBytes
        }
        return Pair(len, bytesConsumed)
    }

    /**
     * Base64url encodes a byte array.
     */
    private fun encodeBase64Url(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    /**
     * Helper to decode Base64url strings (for internal verification/debugging if needed)
     */
    private fun decodeBase64Url(encodedString: String): ByteArray {
        return Base64.decode(encodedString, Base64.URL_SAFE)
    }

    private fun createJwkFromPublicKey(publicKey: PublicKey): JSONObject {
        if (publicKey !is ECKey) { // ECKey is an interface implemented by ECPublicKey
            throw IllegalArgumentException("Public key is not an EC key.")
        }

        val ecPublicKey = publicKey as ECPublicKey // Cast to ECPublicKey to access its params
        val ecPoint: ECPoint = ecPublicKey.w // The affine coordinates (x, y)

        // JWS uses uncompressed elliptic curve points for 'x' and 'y'
        val x = ecPoint.affineX.toByteArray()
        val y = ecPoint.affineY.toByteArray()

        // Remove leading zero byte if present (BigInteger.toByteArray can add it for positive numbers)
        val xBytes =
            if (x.size > 1 && x[0] == 0x00.toByte() && x[1].toInt() and 0x80 == 0x80) x.copyOfRange(
                1,
                x.size
            ) else x
        val yBytes =
            if (y.size > 1 && y[0] == 0x00.toByte() && y[1].toInt() and 0x80 == 0x80) y.copyOfRange(
                1,
                y.size
            ) else y

        return JSONObject().apply {
            put("kty", "EC")
            put("crv", "P-256") // For ES256, it's P-256 (secp256r1)
            put("x", encodeBase64Url(xBytes))
            put("y", encodeBase64Url(yBytes))
        }
    }

    private fun signData(data: ByteArray, privateKey: PrivateKey): ByteArray? {
        try {
            // For ES256, the algorithm is SHA256withECDSA
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)
            signature.update(data)
            return signature.sign()
        } catch (e: Exception) {
            println("Error signing data: ${e.message}")
            e.printStackTrace()
        }
        return null
    }

    /**
     * Generates the SHA-256 JWK Key Thumbprint (jkt) of the DPoP Public Key.
     * This value is typically sent to the Authorization Server to be included in the access token's cnf claim.
     *
     * @return The Base64url encoded JWK Thumbprint, or null if an error occurs.
     */
    public fun getDpopJktValue(): String? {
        if(!keyStoreManager.hasKeyPair()){
            keyStoreManager.generateKeyPair()
        }
        val keyPair = keyStoreManager.getEs256KeyPair()
        if (keyPair == null) {
            println("Key pair not found to generate DPoP jkt.")
            return null
        }

        val publicKey = keyPair.second
        if (publicKey !is ECPublicKey) {
            println("Public key is not an EC key, cannot generate JWK thumbprint.")
            return null
        }

        try {
            // 1. Create the canonical JWK representation of the public key.
            // The order of members in the JWK MUST be lexicographical.
            // Per RFC 7638, for EC keys, the required members are "crv", "kty", "x", and "y".
            val jwkJson = JSONObject().apply {
                put("crv", "P-256")
                put("kty", "EC")
                put("x", encodeBase64Url(getJwkCoordinateBytes(publicKey.w.affineX)))
                put("y", encodeBase64Url(getJwkCoordinateBytes(publicKey.w.affineY)))
            }

            // The order for EC keys (P-256 specifically): crv, kty, x, y
            // Create a sorted JSON string manually for precise canonicalization.
            // This is crucial for consistent thumbprint calculation.
            val canonicalJsonString = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"${
                encodeBase64Url(
                    getJwkCoordinateBytes(publicKey.w.affineX)
                )
            }\",\"y\":\"${encodeBase64Url(getJwkCoordinateBytes(publicKey.w.affineY))}\"}"

            println("Canonical JWK String for jkt: $canonicalJsonString")

            // 2. Compute the SHA-256 hash of the UTF-8 representation of the canonical JWK.
            val sha256Digest = MessageDigest.getInstance("SHA-256")
            val hashBytes = sha256Digest.digest(canonicalJsonString.toByteArray(Charsets.UTF_8))

            // 3. Base64url encode the hash.
            return encodeBase64Url(hashBytes)

        } catch (e: Exception) {
            println("Error generating DPoP jkt value: ${e.message}")
            e.printStackTrace()
        }
        return null
    }

    private fun getJwkCoordinateBytes(coordinate: BigInteger): ByteArray {
        var bytes = coordinate.toByteArray()
        // Remove leading zero byte if present (BigInteger.toByteArray for positive numbers)
        if (bytes.size > 1 && bytes[0] == 0x00.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        // Pad with leading zeros to 32 bytes for P-256 (256 bits / 8 bits/byte = 32 bytes)
        if (bytes.size < 32) {
            val paddedBytes = ByteArray(32)
            System.arraycopy(bytes, 0, paddedBytes, 32 - bytes.size, bytes.size)
            return paddedBytes
        }
        return bytes
    }


    public fun hasKeyPair():Boolean {
        return keyStoreManager.hasKeyPair()
    }

}
