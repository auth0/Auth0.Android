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
import com.auth0.android.result.AuthenticationMethod
import com.auth0.android.result.AuthenticationMethods
import com.auth0.android.result.EnrollmentChallenge
import com.auth0.android.result.Factor
import com.auth0.android.result.Factors
import com.auth0.android.result.PasskeyAuthenticationMethod
import com.auth0.android.result.PasskeyEnrollmentChallenge
import com.auth0.android.result.PasskeyRegistrationChallenge
import com.auth0.android.result.RecoveryCodeEnrollmentChallenge
import com.auth0.android.result.TotpEnrollmentChallenge

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
 * , or alternatively [com.auth0.android.authentication.AuthenticationAPIClient.renewAuth] if you are not using CredentialsManager.
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
        GsonProvider.gson
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
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        val params = ParameterBuilder.newBuilder().apply {
            set(TYPE_KEY, "passkey")
            userIdentity?.let { set(USER_IDENTITY_ID_KEY, it) }
            connection?.let { set(CONNECTION_KEY, it) }
        }.asDictionary()

        val passkeyEnrollmentAdapter: JsonAdapter<PasskeyEnrollmentChallenge> =
            object : JsonAdapter<PasskeyEnrollmentChallenge> {
                override fun fromJson(
                    reader: Reader, metadata: Map<String, Any>
                ): PasskeyEnrollmentChallenge {
                    val location = (metadata[LOCATION_KEY] as? List<*>)?.filterIsInstance<String>()
                        ?.firstOrNull()
                    val authId =
                        location?.split("/")?.lastOrNull()?.let { URLDecoder.decode(it, "UTF-8") }
                            ?: throw MyAccountException("Authentication method ID not found in Location header.")
                    val challenge = gson.fromJson(reader, PasskeyRegistrationChallenge::class.java)
                    return PasskeyEnrollmentChallenge(
                        authId,
                        challenge.authSession,
                        challenge.authParamsPublicKey
                    )
                }
            }
        return factory.post(url.toString(), passkeyEnrollmentAdapter)
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
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
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(challenge.authenticationMethodId)
            .addPathSegment(VERIFY)
            .build()

        val authnResponse = mapOf(
            "authenticatorAttachment" to "platform",
            "clientExtensionResults" to credentials.clientExtensionResults,
            "id" to credentials.id,
            "rawId" to credentials.rawId,
            "type" to "public-key",
            "response" to mapOf(
                "clientDataJSON" to credentials.response.clientDataJSON,
                "attestationObject" to credentials.response.attestationObject,
            )
        )

        val params = ParameterBuilder.newBuilder()
            .set(AUTH_SESSION_KEY, challenge.authSession)
            .asDictionary()

        return factory.post(
            url.toString(),
            GsonAdapter(PasskeyAuthenticationMethod::class.java, gson)
        )
            .addParameters(params)
            .addParameter(AUTHN_RESPONSE_KEY, authnResponse)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }


    /**
     * Retrieves a detailed list of authentication methods belonging to the user.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     *
     * apiClient.getAuthenticationMethods()
     *     .start(object : Callback<List<AuthenticationMethod>, MyAccountException> {
     *         override fun onSuccess(result: List<AuthenticationMethod>) {
     *             Log.d("MyApp", "Authentication methods: $result")
     *         }
     *
     *         override fun onFailure(error: MyAccountException) {
     *             Log.e("MyApp", "Failed with: ${error.message}")
     *         }
     *     })
     * ```
     *
     */
    public fun getAuthenticationMethods(): Request<List<AuthenticationMethod>, MyAccountException> {
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()

        val listAdapter = object : JsonAdapter<List<AuthenticationMethod>> {
            override fun fromJson(reader: Reader, metadata: Map<String, Any>): List<AuthenticationMethod> {
                val container = gson.fromJson(reader, AuthenticationMethods::class.java)
                return container.authenticationMethods
            }
        }
        return factory.get(url.toString(), listAdapter)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }


    /**
     * Retrieves a single authentication method belonging to the user.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     *
     * apiClient.getAuthenticationMethodById(authenticationMethodId, )
     *     .start(object : Callback<AuthenticationMethod, MyAccountException> {
     *         override fun onSuccess(result: AuthenticationMethod) {
     *             Log.d("MyApp", "Authentication method $result")
     *         }
     *
     *         override fun onFailure(error: MyAccountException) {
     *             Log.e("MyApp", "Failed with: ${error.message}")
     *         }
     *     })
     * ```
     *
     * @param authenticationMethodId  Id of the authentication method to be retrieved
     *
     */
    public fun getAuthenticationMethodById(authenticationMethodId: String): Request<AuthenticationMethod, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .build()
        return factory.get(url.toString(), GsonAdapter(AuthenticationMethod::class.java, gson))
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Updates a single authentication method belonging to the user.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     *
     * apiClient.updateAuthenticationMethodById(authenticationMethodId,preferredAuthenticationMethod, authenticationMethodName)
     *     .start(object : Callback<AuthenticationMethod, MyAccountException> {
     *         override fun onSuccess(result: AuthenticationMethod) {
     *             Log.d("MyApp", "Authentication method $result")
     *         }
     *
     *         override fun onFailure(error: MyAccountException) {
     *             Log.e("MyApp", "Failed with: ${error.message}")
     *         }
     *     })
     * ```
     *
     * @param authenticationMethodId  Id of the authentication method to be retrieved
     * @param authenticationMethodName  The friendly name of the authentication method
     * @param preferredAuthenticationMethod The preferred authentication method for the user. (for phone authenticators)
     *
     */
    @JvmOverloads
    internal fun updateAuthenticationMethodById(
        authenticationMethodId: String,
        authenticationMethodName: String? = null,
        preferredAuthenticationMethod: PhoneAuthenticationMethodType? = null
    ): Request<AuthenticationMethod, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .build()

        val params = ParameterBuilder.newBuilder().apply {
            authenticationMethodName?.let { set(AUTHENTICATION_METHOD_NAME, it) }
            preferredAuthenticationMethod?.let {
                set(
                    PREFERRED_AUTHENTICATION_METHOD,
                    it.value
                )
            }
        }.asDictionary()

        return factory.patch(url.toString(), GsonAdapter(AuthenticationMethod::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }


    /**
     * Deletes an existing authentication method belonging to the user.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * ## Scopes Required
     * `delete:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     *
     * apiClient.deleteAuthenticationMethod(authenticationMethodId)
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
    public fun deleteAuthenticationMethod(authenticationMethodId: String): Request<Void?, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .build()
        val voidAdapter = object : JsonAdapter<Void?> {
            override fun fromJson(reader: Reader, metadata: Map<String, Any>): Void? = null
        }
        return factory.delete(url.toString(), voidAdapter)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Gets the list of factors available for the user to enroll.
     *
     * ## Scopes Required
     * `read:me:factors`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.getFactors()
     *      .start(object : Callback<List<Factor>, MyAccountException> {
     *          override fun onSuccess(result: List<Factor>) {
     *              Log.d("MyApp", "Available factors: $result")
     *          }
     *          override fun onFailure(error: MyAccountException) {
     *              Log.e("MyApp", "Error getting factors: $error")
     *      }
     *   })
     * ```
     * @return A request to get the list of available factors.
     */
    public fun getFactors(): Request<List<Factor>, MyAccountException> {
        val url = getDomainUrlBuilder().addPathSegment(FACTORS).build()

        val listAdapter = object : JsonAdapter<List<Factor>> {
            override fun fromJson(reader: Reader, metadata: Map<String, Any>): List<Factor> {
                val container = gson.fromJson(reader, Factors::class.java)
                return container.factors
            }
        }
        return factory.get(url.toString(), listAdapter)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Starts the enrollment of a phone authentication method.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.enrollPhone("+11234567890", "sms")
     *      .start(object : Callback<EnrollmentChallenge, MyAccountException> {
     *          override fun onSuccess(result: EnrollmentChallenge) {
     *          // The enrollment has started. 'result.id' contains the ID for verification.
     *              Log.d("MyApp", "Enrollment started. ID: ${result.id}")
     *           }
     *          override fun onFailure(error: MyAccountException) {
     *              Log.e("MyApp", "Failed with: ${error.message}")
     *          }
     *      })
     * ```
     * @param phoneNumber The phone number to enroll in E.164 format.
     * @param preferredMethod The preferred method for this factor ("sms" or "voice").
     * @return A request that will yield an enrollment challenge.
     */
    public fun enrollPhone(
        phoneNumber: String,
        preferredMethod: PhoneAuthenticationMethodType
    ): Request<EnrollmentChallenge, MyAccountException> {
        val params = ParameterBuilder.newBuilder()
            .set(TYPE_KEY, "phone")
            .set(PHONE_NUMBER_KEY, phoneNumber)
            .set(PREFERRED_AUTHENTICATION_METHOD, preferredMethod.value)
            .asDictionary()
        return buildEnrollmentRequest(params)
    }

    /**
     * Starts the enrollment of an email authentication method.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.enrollEmail("user@example.com")
     *      .start(object : Callback<EnrollmentChallenge, MyAccountException> {
     *           override fun onSuccess(result: EnrollmentChallenge) {
     *       // The enrollment has started. 'result.id' contains the ID for verification.
     *               Log.d("MyApp", "Enrollment started. ID: ${result.id}")
     *          }
     *           override fun onFailure(error: MyAccountException) {
     *               Log.e("MyApp", "Failed with: ${error.message}")
     *          }
     *      })
     * ```
     * @param email the email address to enroll.
     * @return a request that will yield an enrollment challenge.
     */
    public fun enrollEmail(email: String): Request<EnrollmentChallenge, MyAccountException> {
        val params = ParameterBuilder.newBuilder()
            .set(TYPE_KEY, "email")
            .set(EMAIL_KEY, email)
            .asDictionary()
        return buildEnrollmentRequest(params)
    }

    /**
     * Starts the enrollment of a TOTP (authenticator app) method.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.enrollTotp()
     *      .start(object : Callback<TotpEnrollmentChallenge, MyAccountException> {
     *            override fun onSuccess(result: EnrollmentChallenge) {
     *        // The result will be a TotpEnrollmentChallenge with a barcode_uri
     *                  Log.d("MyApp", "Enrollment started for TOTP.")
     *            }
     *           override fun onFailure(error: MyAccountException) { //... }
     *      })
     * ```
     * @return a request that will yield an enrollment challenge.
     */
    public fun enrollTotp(): Request<TotpEnrollmentChallenge, MyAccountException> {
        val params = ParameterBuilder.newBuilder().set(TYPE_KEY, "totp").asDictionary()
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        val adapter = GsonAdapter(TotpEnrollmentChallenge::class.java, gson)
        return factory.post(url.toString(), adapter)
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Starts the enrollment of a Push Notification authenticator.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.enrollPushNotification()
     *      .start(object : Callback<TotpEnrollmentChallenge, MyAccountException> {
     *          override fun onSuccess(result: EnrollmentChallenge) {
     *          // The result will be a TotpEnrollmentChallenge containing a barcode_uri
     *                 Log.d("MyApp", "Enrollment started for Push Notification.")
     *           }
     *          override fun onFailure(error: MyAccountException) { //... }
     *       })
     * ```
     * @return a request that will yield an enrollment challenge.
     */
    public fun enrollPushNotification(): Request<TotpEnrollmentChallenge, MyAccountException> {
        val params = ParameterBuilder.newBuilder().set(TYPE_KEY, "push-notification").asDictionary()
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        // The response structure for push notification challenge is the same as TOTP (contains barcode_uri)
        val adapter = GsonAdapter(TotpEnrollmentChallenge::class.java, gson)
        return factory.post(url.toString(), adapter)
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Starts the enrollment of a Recovery Code authenticator.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.enrollRecoveryCode()
     *      .start(object : Callback<RecoveryCodeEnrollmentChallenge, MyAccountException> {
     *          override fun onSuccess(result: EnrollmentChallenge) {
     *      // The result will be a RecoveryCodeEnrollmentChallenge containing the code
     *              Log.d("MyApp", "Recovery Code enrollment started.")
     *          }
     *          override fun onFailure(error: MyAccountException) { //... }
     *      })
     * ```
     * @return a request that will yield an enrollment challenge containing the recovery code.
     */
    public fun enrollRecoveryCode(): Request<RecoveryCodeEnrollmentChallenge, MyAccountException> {
        val params = ParameterBuilder.newBuilder().set(TYPE_KEY, "recovery-code").asDictionary()
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        val adapter = GsonAdapter(RecoveryCodeEnrollmentChallenge::class.java, gson)
        return factory.post(url.toString(), adapter)
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Confirms the enrollment of a phone, email, or TOTP method by providing the one-time password (OTP).
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * val authMethodId = "from_enrollment_challenge"
     * val authSession = "from_enrollment_challenge"
     * val otp = "123456"
     *
     * apiClient.verifyOtp(authMethodId, otp, authSession)
     *      .start(object : Callback<AuthenticationMethod, MyAccountException> {
     *              override fun onSuccess(result: AuthenticationMethod) { //... }
     *              override fun onFailure(error: MyAccountException) { //... }
     *       })
     * ```
     * @param authenticationMethodId The ID of the method being verified (from the enrollment challenge).
     * @param otpCode The OTP code sent to the user's phone or email, or from their authenticator app.
     * @param authSession The auth session from the enrollment challenge.
     * @return a request that will yield the newly verified authentication method.
     */
    public fun verifyOtp(
        authenticationMethodId: String,
        otpCode: String,
        authSession: String
    ): Request<AuthenticationMethod, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .addPathSegment(VERIFY)
            .build()
        val params = mapOf("otp_code" to otpCode, AUTH_SESSION_KEY to authSession)
        return factory.post(url.toString(), GsonAdapter(AuthenticationMethod::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Confirms the enrollment for factors that do not require an OTP.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * val authMethodId = "from_enrollment_challenge"
     * val authSession = "from_enrollment_challenge"
     *
     * apiClient.verify(authMethodId, authSession)
     *      .start(object : Callback<AuthenticationMethod, MyAccountException> {
     *            override fun onSuccess(result: AuthenticationMethod) { //... }
     *            override fun onFailure(error: MyAccountException) { //... }
     *       })
     * ```
     * @param authenticationMethodId The ID of the method being verified (from the enrollment challenge).
     * @param authSession The auth session from the enrollment challenge.
     * @return a request that will yield the newly verified authentication method.
     */
    public fun verify(
        authenticationMethodId: String,
        authSession: String
    ): Request<AuthenticationMethod, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .addPathSegment(VERIFY)
            .build()
        val params = mapOf(AUTH_SESSION_KEY to authSession)
        return factory.post(url.toString(), GsonAdapter(AuthenticationMethod::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    // WebAuthn methods are private.
    /**
     * Starts the enrollment of a WebAuthn Platform (e.g., biometrics) authenticator.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.enrollWebAuthnPlatform()
     *          .start(object : Callback<EnrollmentChallenge, MyAccountException> {
     *              override fun onSuccess(result: EnrollmentChallenge) {
     *                Log.d("MyApp", "Enrollment started for WebAuthn Platform.")
     *              }
     *              override fun onFailure(error: MyAccountException) { //... }
     *          })
     * ```
     * @return a request that will yield an enrollment challenge.
     */
    private fun enrollWebAuthnPlatform(): Request<EnrollmentChallenge, MyAccountException> {
        val params = ParameterBuilder.newBuilder().set(TYPE_KEY, "webauthn-platform").asDictionary()
        return buildEnrollmentRequest(params)
    }

    /**
     * Starts the enrollment of a WebAuthn Roaming (e.g., security key) authenticator.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * ## Usage
     *
     * ```kotlin
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val apiClient = MyAccountAPIClient(auth0, accessToken)
     *
     * apiClient.enrollWebAuthnRoaming()
     *      .start(object : Callback<EnrollmentChallenge, MyAccountException> {
     *          override fun onSuccess(result: EnrollmentChallenge) {
     *          // The result will be a PasskeyEnrollmentChallenge for WebAuthn
     *              Log.d("MyApp", "Enrollment started for WebAuthn Roaming.")
     *          }
     *          override fun onFailure(error: MyAccountException) { //... }
     *      })
     * ```
     * @return a request that will yield an enrollment challenge.
     */
    private fun enrollWebAuthnRoaming(): Request<EnrollmentChallenge, MyAccountException> {
        val params = ParameterBuilder.newBuilder().set(TYPE_KEY, "webauthn-roaming").asDictionary()
        return buildEnrollmentRequest(params)
    }

    private fun buildEnrollmentRequest(params: Map<String, String>): Request<EnrollmentChallenge, MyAccountException> {
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        return factory.post(url.toString(), GsonAdapter(EnrollmentChallenge::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
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
        private const val PREFERRED_AUTHENTICATION_METHOD = "preferred_authentication_method"
        private const val AUTHENTICATION_METHOD_NAME = "name"
        private const val FACTORS = "factors"
        private const val PHONE_NUMBER_KEY = "phone_number"
        private const val EMAIL_KEY = "email"

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

