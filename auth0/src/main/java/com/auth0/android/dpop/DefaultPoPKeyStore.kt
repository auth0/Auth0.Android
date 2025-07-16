package com.auth0.android.dpop

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import com.auth0.android.authentication.storage.IncompatibleDeviceException
import com.auth0.android.request.AuthenticationRequest
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


public interface PoPKeyStore {

}

@RequiresApi(Build.VERSION_CODES.M)
public class DefaultPoPKeyStore : PoPKeyStore {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }
    }

    public fun generateKeyPair(context: Context) {
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
                if (isStrongBoxEnabled(context)) {
                    setIsStrongBoxBacked(true)
                }
            }

            keyPairGenerator.initialize(builder.build())
            keyPairGenerator.generateKeyPair()
            Log.d(TAG, "Key pair generated successfully.")
        } catch (e: Exception) {

            //TODO : Handle the exceptions beeter with bettr type

            /*
             * This exceptions are safe to be ignored:
             *
             * - CertificateException:
             *      Thrown when certificate has expired (25 years..) or couldn't be loaded
             * - KeyStoreException:
             * - NoSuchProviderException:
             *      Thrown when "AndroidKeyStore" is not available. Was introduced on API 18.
             * - NoSuchAlgorithmException:
             *      Thrown when "RSA" algorithm is not available. Was introduced on API 18.
             * - InvalidAlgorithmParameterException:
             *      Thrown if Key Size is other than 512, 768, 1024, 2048, 3072, 4096
             *      or if Padding is other than RSA/ECB/PKCS1Padding, introduced on API 18
             *      or if Block Mode is other than ECB
             * - ProviderException:
             *      Thrown on some modified devices when KeyPairGenerator#generateKeyPair is called.
             *      See: https://www.bountysource.com/issues/45527093-keystore-issues
             *
             * However if any of this exceptions happens to be thrown (OEMs often change their Android distribution source code),
             * all the checks performed in this class wouldn't matter and the device would not be compatible at all with it.
             *
             * Read more in https://developer.android.com/training/articles/keystore#SupportedAlgorithms
             */
            when (e) {
                is CertificateException,
                is InvalidAlgorithmParameterException,
                is NoSuchProviderException,
                is NoSuchAlgorithmException,
                is KeyStoreException,
                is ProviderException -> {
                    Log.e(TAG, "The device can't generate a new EC Key pair.", e)
                    throw IncompatibleDeviceException(e)
                }

                else -> throw e
            }
        }
    }

    public fun getKeyPair(): Pair<PrivateKey, PublicKey>? {
        try {
            val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
            val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey
            if (privateKey != null && publicKey != null) {
                return Pair(privateKey, publicKey)
            }
        } catch (e: KeyStoreException) {
            Log.e(TAG, "getKeyPair: Error getting key pair ${e.stackTraceToString()}")
        }
        Log.e(TAG, "Returning null key pair ")
        return null
    }


    public fun addHeaders(request: AuthenticationRequest, tokenType: String) {


    }

    public fun hasKeyPair(): Boolean {
        try {
            return keyStore.containsAlias(KEY_ALIAS)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        }
        return false
    }

    public fun deleteKeyPair() {
        try {
            keyStore.deleteEntry(KEY_ALIAS)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
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