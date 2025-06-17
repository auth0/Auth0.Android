package com.auth0.android.myaccount

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.auth0.android.result.PasskeyAuthenticationMethod
import com.auth0.android.result.PasskeyEnrollmentChallenge
import com.auth0.android.result.PasskeyRegistrationChallenge
import com.google.gson.Gson
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader
import java.net.URLDecoder


/**
 * Auth0 My Account API client for managing the current user's account.
 *
 * You can use the refresh token to get an access token for the My Account API. Refer to [com.auth0.android.authentication.storage.CredentialsManager.getApiCredentials]
 *  , or alternatively [com.auth0.android.authentication.AuthenticationAPIClient.renewAuth] if you are not using CredentialsManager.
 *
 * ## Usage
 * ```kotlin
 * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 * val client = MyAccountAPIClient(auth0,accessToken)
 * ```
 *
 *
 */
public class MyAccountAPIClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val accessToken: String,
    private val factory: RequestFactory<MyAccountException>,
    private val gson: Gson
) {

    /**
     * Creates a new MyAccountAPI client instance.
     *
     * Example usage:
     *
     * ```
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val client = MyAccountAPIClient(auth0, accessToken)
     * ```
     * @param auth0 account information
     */
    public constructor(
        auth0: Auth0,
        accessToken: String
    ) : this(
        auth0,
        accessToken,
        RequestFactory<MyAccountException>(auth0.networkingClient, createErrorAdapter()),
        Gson()
    )


    /**
     * Requests a challenge for enrolling a new passkey. This is the first part of the enrollment flow.
     *
     * You can specify an optional user identity identifier and an optional database connection name.
     * If a connection name is not specified, your tenant's default directory will be used.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * ## Scopes Required
     *
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.passkeyEnrollmentChallenge()
     *     .start(object : Callback<PasskeyEnrollmentChallenge, MyAccountException> {
     *         override fun onSuccess(result: PasskeyEnrollmentChallenge) {
     *             // Use the challenge with Credential Manager API to generate a new passkey credential
     *             Log.d("MyApp", "Obtained enrollment challenge: $result")
     *         }
     *
     *         override fun onFailure(error: MyAccountException) {
     *             Log.e("MyApp", "Failed with: ${error.message}")
     *         }
     *     })
     * ```
     * Use the challenge with [Google Credential Manager API](https://developer.android.com/identity/sign-in/credential-manager) to generate a new passkey credential.
     *
     * ``` kotlin
     *  CreatePublicKeyCredentialRequest( Gson().
     *      toJson( passkeyEnrollmentChallenge.authParamsPublicKey ))
     *            var response: CreatePublicKeyCredentialResponse?
     *            credentialManager.createCredentialAsync(
     *               requireContext(),
     *               request,
     *               CancellationSignal(),
     *               Executors.newSingleThreadExecutor(),
     *               object :
     *                    CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
     *                        override fun onError(e: CreateCredentialException) {
     *                        }
     *
     *                        override fun onResult(result: CreateCredentialResponse) {
     *                           response = result as CreatePublicKeyCredentialResponse
     *                           val credentials = Gson().fromJson(
     *                               response?.registrationResponseJson, PublicKeyCredentials::class.java
     *                             )
     *                        }
     * ```
     *
     * Then, call ``enroll()`` with the created passkey credential and the challenge to complete
     * the enrollment.
     *
     * @param userIdentity Unique identifier of the current user's identity. Needed if the user logged in with a [linked account](https://auth0.com/docs/manage-users/user-accounts/user-account-linking)
     * @param connection Name of the database connection where the user is stored
     * @return A request to obtain a passkey enrollment challenge
     *
     * */
    @JvmOverloads
    public fun passkeyEnrollmentChallenge(
        userIdentity: String? = null, connection: String? = null
    ): Request<PasskeyEnrollmentChallenge, MyAccountException> {

        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .build()

        val params = ParameterBuilder.newBuilder().apply {
            set(TYPE_KEY, "passkey")
            userIdentity?.let {
                set(USER_IDENTITY_ID_KEY, userIdentity)
            }
            connection?.let {
                set(CONNECTION_KEY, connection)
            }
        }.asDictionary()

        val passkeyEnrollmentAdapter: JsonAdapter<PasskeyEnrollmentChallenge> =
            object : JsonAdapter<PasskeyEnrollmentChallenge> {
                override fun fromJson(
                    reader: Reader, metadata: Map<String, Any>
                ): PasskeyEnrollmentChallenge {
                    val headers = metadata.mapValues { (_, value) ->
                        when (value) {
                            is List<*> -> value.filterIsInstance<String>()
                            else -> emptyList()
                        }
                    }
                    val locationHeader = headers[LOCATION_KEY]?.get(0)?.split("/")?.lastOrNull()
                    locationHeader ?: throw MyAccountException("Authentication method ID not found")
                    val authenticationId =
                        URLDecoder.decode(
                            locationHeader,
                            "UTF-8"
                        )

                    val passkeyRegistrationChallenge = gson.fromJson<PasskeyRegistrationChallenge>(
                        reader, PasskeyRegistrationChallenge::class.java
                    )
                    return PasskeyEnrollmentChallenge(
                        authenticationId,
                        passkeyRegistrationChallenge.authSession,
                        passkeyRegistrationChallenge.authParamsPublicKey
                    )
                }
            }
        val post = factory.post(url.toString(), passkeyEnrollmentAdapter)
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")

        return post
    }

    /**
     * Enrolls a new passkey credential. This is the last part of the enrollment flow.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * ## Scopes Required
     *
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * // After obtaining the passkey credential from the [Credential Manager API](https://developer.android.com/identity/sign-in/credential-manager)
     * apiClient.enroll(publicKeyCredentials, enrollmentChallenge)
     *     .start(object : Callback<PasskeyAuthenticationMethod, MyAccountException> {
     *         override fun onSuccess(result: AuthenticationMethodVerified) {
     *             Log.d("MyApp", "Enrolled passkey: $result")
     *         }
     *
     *         override fun onFailure(error: MyAccountException) {
     *             Log.e("MyApp", "Failed with: ${error.message}")
     *         }
     *     })
     * ```
     *
     * @param credentials The passkey credentials obtained from the [Credential Manager API](https://developer.android.com/identity/sign-in/credential-manager).
     * @param challenge The enrollment challenge obtained from the `passkeyEnrollmentChallenge()` method.
     * @return A request to enroll the passkey credential.
     */
    public fun enroll(
        credentials: PublicKeyCredentials, challenge: PasskeyEnrollmentChallenge
    ): Request<PasskeyAuthenticationMethod, MyAccountException> {
        val authMethodId = challenge.authenticationMethodId
        val url =
            getDomainUrlBuilder()
                .addPathSegment(AUTHENTICATION_METHODS)
                .addPathSegment(authMethodId)
                .addPathSegment(VERIFY)
                .build()

        val authenticatorResponse = mapOf(
            "authenticatorAttachment" to "platform",
            "clientExtensionResults" to credentials.clientExtensionResults,
            "id" to credentials.id,
            "rawId" to credentials.rawId,
            "type" to "public-key",
            "response" to mapOf(
                "clientDataJSON" to credentials.response.clientDataJSON,
                "attestationObject" to credentials.response.attestationObject
            )
        )

        val params = ParameterBuilder.newBuilder().apply {
            set(AUTH_SESSION_KEY, challenge.authSession)
        }.asDictionary()

        val passkeyAuthenticationAdapter = GsonAdapter(
            PasskeyAuthenticationMethod::class.java
        )

        val request = factory.post(
            url.toString(), passkeyAuthenticationAdapter
        ).addParameters(params)
            .addParameter(AUTHN_RESPONSE_KEY, authenticatorResponse)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
        return request
    }


    /**
     * Deletes an  existing authentication method.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * ## Scopes Required
     * `delete:me:authentication-methods:passkey`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     *
     * apiClient.delete(authenticationMethodId, )
     *     .start(object : Callback<Void, MyAccountException> {
     *         override fun onSuccess(result: Void) {
     *             Log.d("MyApp", "Authentication method deleted")
     *         }
     *
     *         override fun onFailure(error: MyAccountException) {
     *             Log.e("MyApp", "Failed with: ${error.message}")
     *         }
     *     })
     * ```
     *
     * @param authenticationMethodId  Id of the authentication method to be deleted
     *
     */
    public fun delete(
        authenticationMethodId: String
    ): Request<Void, MyAccountException> {
        val url =
            getDomainUrlBuilder()
                .addPathSegment(AUTHENTICATION_METHODS)
                .addPathSegment(authenticationMethodId)
                .build()

        val request = factory.delete(url.toString(), GsonAdapter(Void::class.java))
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")

        return request
    }


    private fun getDomainUrlBuilder(): HttpUrl.Builder {
        return auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(ME_PATH)
            .addPathSegment(API_VERSION)
    }


    private companion object {
        private const val AUTHENTICATION_METHODS = "authentication-methods"
        private const val VERIFY = "verify"
        private const val API_VERSION = "v1"
        private const val ME_PATH = "me"
        private const val TYPE_KEY = "type"
        private const val USER_IDENTITY_ID_KEY = "identity_user_id"
        private const val CONNECTION_KEY = "connection"
        private const val AUTHORIZATION_KEY = "Authorization"
        private const val LOCATION_KEY = "location"
        private const val AUTH_SESSION_KEY = "auth_session"
        private const val AUTHN_RESPONSE_KEY = "authn_response"
        private fun createErrorAdapter(): ErrorAdapter<MyAccountException> {
            val mapAdapter = forMap(GsonProvider.gson)
            return object : ErrorAdapter<MyAccountException> {
                override fun fromRawResponse(
                    statusCode: Int, bodyText: String, headers: Map<String, List<String>>
                ): MyAccountException {
                    return MyAccountException(bodyText, statusCode)
                }

                @Throws(IOException::class)
                override fun fromJsonResponse(
                    statusCode: Int, reader: Reader
                ): MyAccountException {
                    val values = mapAdapter.fromJson(reader)
                    return MyAccountException(values, statusCode)
                }

                override fun fromException(cause: Throwable): MyAccountException {
                    if (isNetworkError(cause)) {
                        return MyAccountException(
                            "Failed to execute the network request", NetworkErrorException(cause)
                        )
                    }
                    return MyAccountException(
                        cause.message ?: "Something went wrong",
                        Auth0Exception(cause.message ?: "Something went wrong", cause)
                    )
                }
            }
        }
    }
}