package com.auth0.android.dpop

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

public class KeyStoreManager {

    private val ANDROID_KEY_STORE = "AndroidKeyStore"
    private val KEY_ALIAS = "dpop_signature_key"

    @RequiresApi(Build.VERSION_CODES.M)
    public fun generateKeyPair(): KeyPair? {

        try {

            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)

            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(256)

            keyPairGenerator.initialize(builder.build())
            val keyPair = keyPairGenerator.generateKeyPair()
            println("ECDSA P-256 Key Pair generated and stored in Android Keystore under alias: dpop_signature_key")
            return keyPair
        } catch (exception: Exception) {
            println("Error generating ECDSA P-256 Key Pair: ${exception.message}")
            exception.printStackTrace()
        }
        return null
    }

    public fun hasKeyPair():Boolean {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore.load(null)
            return keyStore.containsAlias(KEY_ALIAS)
        }catch (exception:Exception){
           println("Error checking for ECDSA P-256 Key Pair: ${exception.message}")
        }
        return false
    }


    public fun getEs256KeyPair(): Pair<PrivateKey, PublicKey>? {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore.load(null) // Load the Keystore

            val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            val certificate = keyStore.getCertificate(KEY_ALIAS)
            val publicKey = certificate?.publicKey

            return if (privateKey != null && publicKey != null) {
                Pair(privateKey, publicKey)
            } else {
                println("Key pair not found for alias: $KEY_ALIAS")
                null
            }
        } catch (e: Exception) {
            println("Key is unrecoverable: ${e.message}")
            e.printStackTrace()
        }
        return null
    }

    public fun deleteKeyPair() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore.load(null) // Load the Keystore
            if (keyStore.containsAlias(ANDROID_KEY_STORE)) {
                keyStore.deleteEntry(ANDROID_KEY_STORE)
                println("Key Pair  deleted successfully.")
            } else {
                println("No Key Pair found with alias")
            }
        } catch (e: Exception) {
            println("Error deleting Key Pair: ${e.message}")
            e.printStackTrace()
        }
    }

}