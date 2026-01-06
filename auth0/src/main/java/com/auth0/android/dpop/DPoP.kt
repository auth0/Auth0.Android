package com.auth0.android.dpop

import android.content.Context
import androidx.annotation.VisibleForTesting
import com.auth0.android.dpop.DPoPUtil.NONCE_REQUIRED_ERROR
import com.auth0.android.dpop.DPoPUtil.generateProof
import com.auth0.android.dpop.DPoPUtil.isResourceServerNonceError
import com.auth0.android.request.HttpMethod
import com.auth0.android.request.getErrorBody
import okhttp3.Response
import java.lang.reflect.Modifier.PRIVATE


/**
 * Data class returning the value that needs to be added to the request for the `Authorization` and `DPoP` headers.
 * @param  authorizationHeader value for the `Authorization` header key
 * @param dpopProof value for the `DPoP header key . This will be generated only for DPoP requests
 */
public data class HeaderData(val authorizationHeader: String, val dpopProof: String?)

/**
 * Class for securing requests with DPoP (Demonstrating Proof of Possession) as described in
 * [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
 */
public class DPoP(context: Context) {

    private val applicationContext: Context = context.applicationContext

    /**
     * Determines whether a DPoP proof should be generated for the given URL and parameters. The proof should
     * only be generated for the `token` endpoint for a fresh login scenario or when a key-pair already exists.
     *
     * @param url The URL of the request
     * @param parameters The request parameters as a map
     * @return true if a DPoP proof should be generated, false otherwise
     * @throws DPoPException if there's an error checking for existing keypair
     */
    @Throws(DPoPException::class)
    internal fun shouldGenerateProof(url: String, parameters: Map<String, Any>): Boolean {
        if (url.endsWith("/token")) {
            val grantType = parameters["grant_type"] as? String
            if (grantType != null && grantType != "refresh_token") {
                return true
            }
        }
        return DPoPUtil.hasKeyPair()
    }

    /**
     * Generates a DPoP proof for the given request.
     *
     * @param request The URL of the request for which to generate the proof.
     * @param httpMethod The HTTP method of the request (e.g., GET, POST).
     * @param header The headers of the request.
     * @return A DPoP proof JWT as a String.
     * @throws DPoPException if the proof generation fails.
     */
    @Throws(DPoPException::class)
    internal fun generateProof(
        request: String,
        httpMethod: HttpMethod,
        header: Map<String, String>
    ): String? {
        val authorizationHeader = header[AUTHORIZATION_HEADER]
        val accessToken = authorizationHeader?.split(" ")?.lastOrNull()

        return generateProof(
            httpUrl = request,
            httpMethod = httpMethod.toString(),
            nonce = auth0Nonce,
            accessToken = accessToken
        )
    }


    /**
     * Generates a new key pair for DPoP if it does not exist. This should be called before making any requests that require a DPoP proof.
     *
     * @param context The application context used to access the keystore.
     * @throws DPoPException if there is an error generating the key pair or accessing the keystore.
     */
    @Throws(DPoPException::class)
    internal fun generateKeyPair() {
        DPoPUtil.generateKeyPair(applicationContext)
    }

    /**
     * Method to get the public key in JWK format. This is used to generate the `jwk` field in the DPoP proof header.
     * This method will also create a key-pair in the key store if one currently doesn't exist.
     *
     * @return The public key in JWK format or null if the key pair is not present.
     * @throws DPoPException if there is an error accessing the key pair.
     */
    @Throws(DPoPException::class)
    internal fun getPublicKeyJWK(): String? {
        generateKeyPair()
        return DPoPUtil.getPublicKeyJWK()
    }

    public companion object {

        private const val AUTHORIZATION_HEADER = "Authorization"
        private const val NONCE_HEADER = "DPoP-Nonce"

        @Volatile
        @VisibleForTesting(otherwise  = PRIVATE)
        internal var _auth0Nonce: String? = null

        public val auth0Nonce: String?
            get() = _auth0Nonce

        /**
         * Stores the nonce value from the Okhttp3 [Response] headers.
         *
         * ```kotlin
         *
         *  try {
         *      DPoP.storeNonce(response)
         *  } catch (exception: Exception) {
         *      Log.e(TAG, "Error storing nonce: ${exception.stackTraceToString()}")
         *  }
         *
         * ```
         *
         * @param response The HTTP response containing the nonce header.
         */
        @JvmStatic
        internal fun storeNonce(response: Response) {
            response.headers[NONCE_HEADER]?.let {
                synchronized(this) {
                    _auth0Nonce = it
                }
            }
        }

        /**
         * Checks if the given [Response] indicates that a nonce is required for DPoP requests.
         * This is typically used to determine if the request needs to be retried with a nonce.
         *
         * ```kotlin
         *
         *  if (DPoP.isNonceRequiredError(response)) {
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
         * Generates the header data for a request that requires DPoP proof of possession. The `Authorization` header value is created
         * using the access token and token type. The `DPoP` header value contains the generated DPoP proof.
         *
         * ```kotlin
         *
         *  try {
         *        val headerData = DPoP.getHeaderData(
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
         * Method to clear the DPoP key pair from the keystore. It must be called when the user logs out
         * to prevent reuse of the key pair in subsequent sessions.
         *
         * ```kotlin
         *
         *  try {
         *      DPoP.clearKeyPair()
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
            DPoPUtil.clearKeyPair()
            _auth0Nonce = null
        }
    }
}