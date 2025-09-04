package com.auth0.android.dpop

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.ProviderException
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import javax.security.auth.x500.X500Principal
import javax.security.cert.CertificateException

/**
 * Class to handle all DPoP related keystore operations
 */
internal open class DPoPKeyStore {

    protected open val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    fun generateKeyPair(context: Context, useStrongBox: Boolean = true) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            throw DPoPException.UNSUPPORTED_ERROR
        }
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )

            val start = Calendar.getInstance()
            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 25)
            val principal = X500Principal("CN=Auth0.Android,O=Auth0")

            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                setCertificateSubject(principal)
                setCertificateNotBefore(start.time)
                setCertificateNotAfter(end.time)
                if (useStrongBox && isStrongBoxEnabled(context)) {
                    setIsStrongBoxBacked(true)
                }
            }

            keyPairGenerator.initialize(builder.build())
            keyPairGenerator.generateKeyPair()
            Log.d(TAG, "Key pair generated successfully.")
        } catch (e: Exception) {
            when (e) {
                is CertificateException,
                is InvalidAlgorithmParameterException,
                is NoSuchProviderException,
                is NoSuchAlgorithmException,
                is KeyStoreException -> {
                    Log.e(TAG, "The device can't generate a new EC Key pair.", e)
                    throw DPoPException(DPoPException.Code.KEY_GENERATION_ERROR, e)
                }

                is ProviderException -> {
                    Log.d(
                        TAG,
                        "Key generation failed. Will retry one time before throwing the exception ${e.stackTraceToString()}"
                    )
                    if (useStrongBox) {
                        // Retry the key-pair generation with strong box disabled
                        generateKeyPair(context, false)
                    } else {
                        throw DPoPException(DPoPException.Code.KEY_GENERATION_ERROR, e)
                    }
                }

                else -> throw DPoPException(DPoPException.Code.UNKNOWN_ERROR, e)
            }
        }
    }

    fun getKeyPair(): Pair<PrivateKey, PublicKey>? {
        try {
            val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
            val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey
            if (publicKey != null) {
                return Pair(privateKey, publicKey)
            }
        } catch (e: KeyStoreException) {
            throw DPoPException(DPoPException.Code.KEY_STORE_ERROR, e)
        }
        Log.d(TAG, "Returning null key pair ")
        return null
    }

    fun hasKeyPair(): Boolean {
        try {
            return keyStore.containsAlias(KEY_ALIAS)
        } catch (e: KeyStoreException) {
            throw DPoPException(DPoPException.Code.KEY_STORE_ERROR, e)
        }
    }

    fun deleteKeyPair() {
        try {
            keyStore.deleteEntry(KEY_ALIAS)
        } catch (e: KeyStoreException) {
            throw DPoPException(DPoPException.Code.KEY_STORE_ERROR, e)
        }
    }

    private fun isStrongBoxEnabled(context: Context): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && context.packageManager.hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE
        )
    }

    private companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "DPoPES256Alias"
        private const val TAG = "DefaultPoPKeyStore"
    }

}