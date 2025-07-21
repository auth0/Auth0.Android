package com.auth0.android.myaccount

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils
import com.auth0.android.result.*
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader

/**
 * Auth0 My Account API client for managing the current user's account.
 *
 * You can use a refresh token to get an access token for the My Account API.
 * Refer to `CredentialsManager#getApiCredentials` or `AuthenticationAPIClient#renewAuth`.
 *
 * ## Usage
 * ```kotlin
 * val auth0 = Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 * val client = MyAccountAPIClient(auth0, accessToken)
 * ```
 */
public class MyAccountAPIClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val accessToken: String,
    private val factory: RequestFactory<MyAccountException>,
    private val gson: Gson
) {

    /**
     * Creates a new MyAccountAPI client instance.
     * @param auth0 your Auth0 account configuration.
     * @param accessToken the user's Access Token with scopes for the My Account API.
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
     * Get the status of all factors available for enrollment.
     *
     * ## Scopes Required
     * `read:me`
     *
     * @return a request to get the list of available factors.
     */
    public fun getFactors(): Request<List<Factor>, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(FACTORS)
            .build()

        val factorListAdapter = object : JsonAdapter<List<Factor>> {
            override fun fromJson(reader: Reader, metadata: Map<String, Any>): List<Factor> {
                val listType = object : TypeToken<List<Factor>>() {}.type
                return gson.fromJson(reader, listType)
            }
        }

        return factory.get(url.toString(), factorListAdapter)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Retrieves a detailed list of authentication methods belonging to the user.
     *
     * ## Scopes Required
     * `read:me:authentication_methods`
     *
     * @return a request to get the list of enrolled authentication methods.
     */
    public fun getAuthenticationMethods(): Request<AuthenticationMethods, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .build()

        return factory.get(url.toString(), GsonAdapter(AuthenticationMethods::class.java, gson))
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Retrieves a single authentication method by its ID.
     *
     * ## Scopes Required
     * `read:me:authentication_methods`
     *
     * @param authenticationMethodId ID of the authentication method to retrieve.
     * @return a request to get the specified authentication method.
     */
    public fun getAuthenticationMethod(authenticationMethodId: String): Request<AuthenticationMethod, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .build()

        return factory.get(url.toString(), GsonAdapter(AuthenticationMethod::class.java, gson))
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Starts the enrollment of a phone authentication method.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * @param phoneNumber the phone number to enroll.
     * @param preferredMethod the preferred method for this factor ("sms" or "voice").
     * @return a request that will yield an enrollment challenge.
     */
    public fun enrollPhone(phoneNumber: String, preferredMethod: String): Request<EnrollmentChallenge, MyAccountException> {
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        val params = ParameterBuilder.newBuilder()
            .set(TYPE_KEY, "phone")
            .set(PHONE_NUMBER_KEY, phoneNumber)
            .set(PREFERRED_AUTHENTICATION_METHOD, preferredMethod)
            .asDictionary()

        return factory.post(url.toString(), GsonAdapter(EnrollmentChallenge::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Starts the enrollment of an email authentication method.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * @param email the email address to enroll.
     * @return a request that will yield an enrollment challenge.
     */
    public fun enrollEmail(email: String): Request<EnrollmentChallenge, MyAccountException> {
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        val params = ParameterBuilder.newBuilder()
            .set(TYPE_KEY, "email")
            .set(EMAIL_KEY, email)
            .asDictionary()

        return factory.post(url.toString(), GsonAdapter(EnrollmentChallenge::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Starts the enrollment of a TOTP (authenticator app) method.
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * @return a request that will yield an enrollment challenge containing a barcode URI.
     */
    public fun enrollTotp(): Request<EnrollmentChallenge, MyAccountException> {
        val url = getDomainUrlBuilder().addPathSegment(AUTHENTICATION_METHODS).build()
        val params = ParameterBuilder.newBuilder()
            .set(TYPE_KEY, "totp")
            .asDictionary()

        return factory.post(url.toString(), GsonAdapter(EnrollmentChallenge::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }


    /**
     * Confirms the enrollment of a phone or email method by providing the one-time password (OTP).
     *
     * ## Scopes Required
     * `create:me:authentication_methods`
     *
     * @param authenticationMethodId the ID of the method being verified (from the enrollment challenge).
     * @param otpCode the OTP code sent to the user's phone or email.
     * @return a request that will yield the newly verified authentication method.
     */
    public fun verify(authenticationMethodId: String, otpCode: String): Request<AuthenticationMethod, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .addPathSegment(VERIFY)
            .build()
        val params = mapOf("otp_code" to otpCode)
        return factory.post(url.toString(), GsonAdapter(AuthenticationMethod::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }


    /**
     * Updates the friendly name of an authentication method.
     *
     * ## Scopes Required
     * `update:me:authentication_methods`
     *
     * @param authenticationMethodId ID of the authentication method to update.
     * @param name the new friendly name for the method.
     * @return a request that will yield the updated authentication method.
     */
    public fun updateAuthenticationMethod(authenticationMethodId: String, name: String): Request<AuthenticationMethod, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .build()

        val params = ParameterBuilder.newBuilder()
            .set(NAME_KEY, name)
            .asDictionary()

        return factory.patch(url.toString(), GsonAdapter(AuthenticationMethod::class.java, gson))
            .addParameters(params)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    /**
     * Deletes an authentication method by its ID.
     *
     * ## Scopes Required
     * `delete:me:authentication_methods`
     *
     * @param authenticationMethodId ID of the authentication method to delete.
     * @return a request that completes when the method is deleted.
     */
    public fun deleteAuthenticationMethod(authenticationMethodId: String): Request<Void, MyAccountException> {
        val url = getDomainUrlBuilder()
            .addPathSegment(AUTHENTICATION_METHODS)
            .addPathSegment(authenticationMethodId)
            .build()

        @Suppress("UNCHECKED_CAST")
        val voidAdapter = GsonAdapter(Void::class.java, gson) as JsonAdapter<Void>
        return factory.delete(url.toString(), voidAdapter)
            .addHeader(AUTHORIZATION_KEY, "Bearer $accessToken")
    }

    private fun getDomainUrlBuilder(): HttpUrl.Builder {
        return auth0.getDomainUrl().toString().toHttpUrl().newBuilder()
            .addPathSegment(ME_PATH)
            .addPathSegment(API_VERSION)
    }

    private companion object {
        private const val API_VERSION = "v1"
        private const val ME_PATH = "me"
        private const val FACTORS = "factors"
        private const val AUTHENTICATION_METHODS = "authentication-methods"
        private const val VERIFY = "verify"
        private const val AUTHORIZATION_KEY = "Authorization"
        private const val NAME_KEY = "name"
        private const val TYPE_KEY = "type"
        private const val PHONE_NUMBER_KEY = "phone_number"
        private const val EMAIL_KEY = "email"
        private const val PREFERRED_AUTHENTICATION_METHOD = "preferred_authentication_method"

        private fun createErrorAdapter(): ErrorAdapter<MyAccountException> {
            val mapAdapter = GsonAdapter.forMap(GsonProvider.gson)
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
                    if (ResponseUtils.isNetworkError(cause)) {
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