package com.auth0.android.request.internal

import android.util.Base64
import android.util.Log
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.JsonParseException
import java.lang.reflect.Type
import java.math.BigInteger
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPublicKeySpec

internal class JwksDeserializer : JsonDeserializer<Map<String, PublicKey>> {
    @Throws(JsonParseException::class)
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type,
        context: JsonDeserializationContext
    ): Map<String, PublicKey> {
        if (!json.isJsonObject || json.isJsonNull || json.asJsonObject.entrySet().isEmpty()) {
            throw JsonParseException("jwks json must be a valid and non-empty json object")
        }
        val jwks = mutableMapOf<String, PublicKey>()
        val keys = json.asJsonObject.getAsJsonArray("keys")
        for (k in keys) {
            val currentKey = k.asJsonObject
            val keyAlg = context.deserialize<String>(currentKey["alg"], String::class.java)
            val keyUse = context.deserialize<String>(currentKey["use"], String::class.java)
            if (RSA_ALGORITHM != keyAlg || USE_SIGNING != keyUse) {
                //Key not supported at this time
                continue
            }
            val keyType = context.deserialize<String>(currentKey["kty"], String::class.java)
            val keyId = context.deserialize<String>(currentKey["kid"], String::class.java)
            val keyModulus = context.deserialize<String>(currentKey["n"], String::class.java)
            val keyPublicExponent = context.deserialize<String>(currentKey["e"], String::class.java)
            try {
                val kf = KeyFactory.getInstance(keyType)
                val modulus = BigInteger(
                    1,
                    Base64.decode(
                        keyModulus,
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    )
                )
                val exponent = BigInteger(
                    1,
                    Base64.decode(
                        keyPublicExponent,
                        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    )
                )
                val pub = kf.generatePublic(RSAPublicKeySpec(modulus, exponent))
                jwks[keyId] = pub
            } catch (e: NoSuchAlgorithmException) {
                Log.e(
                    JwksDeserializer::class.java.simpleName,
                    "Could not parse the JWK with ID $keyId",
                    e
                )
                //Would result in an empty key set
            } catch (e: InvalidKeySpecException) {
                Log.e(
                    JwksDeserializer::class.java.simpleName,
                    "Could not parse the JWK with ID $keyId",
                    e
                )
            }
        }
        return jwks.toMap()
    }

    companion object {
        private const val RSA_ALGORITHM = "RS256"
        private const val USE_SIGNING = "sig"
    }
}