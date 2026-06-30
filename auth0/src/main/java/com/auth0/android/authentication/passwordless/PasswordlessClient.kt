package com.auth0.android.authentication.passwordless

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.dpop.DPoP
import com.auth0.android.dpop.DPoPException
import com.auth0.android.request.AuthenticationRequest
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.Request
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.RequestValidator
import com.auth0.android.request.internal.BaseAuthenticationRequest
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.auth0.android.result.Credentials
import com.auth0.android.result.PasswordlessChallenge
import com.google.gson.Gson
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader

/**
 * API client for the database-connection passwordless authentication flow.
 *
 * Obtain an instance from
 * [com.auth0.android.authentication.AuthenticationAPIClient.passwordlessClient].
 *
 * ## Availability
 *
 * This feature is currently available in
 * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
 * Please reach out to Auth0 support to get it enabled for your tenant.
 *
 * @see com.auth0.android.authentication.AuthenticationAPIClient.passwordlessClient
 */
public class PasswordlessClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val gson: Gson,
    private val dPoP: DPoP?
) {

    private val requestFactory: RequestFactory<AuthenticationException> by lazy {
        RequestFactory(auth0.networkingClient, createErrorAdapter()).apply {
            setAuth0ClientInfo(auth0.auth0UserAgent.value)
        }
    }

    /**
     * Creates a new PasswordlessClient instance.
     *
     * @param auth0 the Auth0 account information.
     */
    public constructor(auth0: Auth0) : this(auth0, GsonProvider.gson, null)

    private val clientId: String = auth0.clientId
    private val baseURL: String = auth0.getDomainUrl()

    /**
     * Issues an OTP challenge to an email address for a database connection.
     *
     * Sends a one-time code to the given email for a connection that has `email_otp` enabled.
     * For privacy, the server **always responds successfully regardless of whether the user
     * exists** (user-enumeration prevention). On success an opaque [PasswordlessChallenge.authSession]
     * is returned — pass it to [loginWithOTP] together with the code the user receives.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * ## Usage
     *
     * ```kotlin
     * passwordless.challengeWithEmail("user@example.com", "Username-Password-Authentication")
     *     .start(object : Callback<PasswordlessChallenge, AuthenticationException> {
     *         override fun onSuccess(result: PasswordlessChallenge) {
     *             val challenge = result
     *         }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param email the email address to send the one-time code to.
     * @param connection the name of the database connection; it must have `email_otp` enabled.
     * @param allowSignup whether to allow sign-up if the user does not yet exist. Defaults to `false`.
     * @return a request that, when started, yields a [PasswordlessChallenge] containing the `auth_session`.
     * @see loginWithOTP
     */
    @JvmOverloads
    public fun challengeWithEmail(
        email: String,
        connection: String,
        allowSignup: Boolean = false
    ): Request<PasswordlessChallenge, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setConnection(connection)
            .set(ALLOW_SIGNUP_KEY, allowSignup.toString())
            .set(EMAIL_KEY, email)
            .asDictionary()
        return challengeRequest(parameters).addValidator(object : RequestValidator {
            override fun validate(options: RequestOptions) {
                requireNotBlank(email, EMAIL_KEY)
                requireNotBlank(connection, CONNECTION_KEY)
            }
        })
    }

    /**
     * Issues an OTP challenge to a phone number for a database connection.
     *
     * Sends a one-time code to the given phone number for a connection that has `phone_otp`
     * enabled, delivered either by SMS or voice call per [deliveryMethod]. For privacy, the server
     * **always responds successfully regardless of whether the user exists**.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * ## Usage
     *
     * ```kotlin
     * passwordless.challengeWithPhoneNumber("+15555550123", "Username-Password-Authentication", DeliveryMethod.TEXT)
     *     .start(object : Callback<PasswordlessChallenge, AuthenticationException> {
     *         override fun onSuccess(result: PasswordlessChallenge) {
     *             val challenge = result
     *         }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param phoneNumber the E.164 phone number to send the one-time code to (e.g. `"+15555550123"`).
     * @param connection the name of the database connection; it must have `phone_otp` enabled.
     * @param deliveryMethod how to deliver the code. Defaults to [DeliveryMethod.TEXT].
     * @param allowSignup whether to allow sign-up if the user does not yet exist. Defaults to `false`.
     * @return a request that, when started, yields a [PasswordlessChallenge] containing the `auth_session`.
     * @see loginWithOTP
     */
    @JvmOverloads
    public fun challengeWithPhoneNumber(
        phoneNumber: String,
        connection: String,
        deliveryMethod: DeliveryMethod = DeliveryMethod.TEXT,
        allowSignup: Boolean = false
    ): Request<PasswordlessChallenge, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setConnection(connection)
            .set(ALLOW_SIGNUP_KEY, allowSignup.toString())
            .set(PHONE_NUMBER_KEY, phoneNumber)
            .set(DELIVERY_METHOD_KEY, deliveryMethod.value)
            .asDictionary()
        return challengeRequest(parameters).addValidator(object : RequestValidator {
            override fun validate(options: RequestOptions) {
                requireNotBlank(phoneNumber, PHONE_NUMBER_KEY)
                requireNotBlank(connection, CONNECTION_KEY)
            }
        })
    }

    /**
     * Completes the OTP flow by verifying the one-time code and obtaining credentials.
     *
     * Exchanges the opaque `auth_session` returned by [challengeWithEmail] or
     * [challengeWithPhoneNumber], together with the code the user received, for [Credentials] using
     * the passwordless OTP grant on `POST /oauth/token`. When DPoP is enabled on the originating
     * [com.auth0.android.authentication.AuthenticationAPIClient], a DPoP proof is attached.
     *
     * ## Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     * ## Usage
     *
     * ```kotlin
     * passwordless.loginWithOTP(challenge, "123456")
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param passwordlessChallenge the challenge from a prior challenge (see [PasswordlessChallenge]).
     * @param otp the one-time code the user received via email, SMS, or voice call.
     * @return a request that, when started, yields [Credentials] on success.
     * @see challengeWithEmail
     * @see challengeWithPhoneNumber
     */
    public fun loginWithOTP(
        passwordlessChallenge: PasswordlessChallenge,
        otp: String
    ): AuthenticationRequest {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()

        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setClientId(clientId)
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
            .set(AUTH_SESSION_KEY, passwordlessChallenge.authSession)
            .set(ONE_TIME_PASSWORD_KEY, otp)
            .asDictionary()

        val credentialsAdapter: JsonAdapter<Credentials> =
            GsonAdapter(Credentials::class.java, gson)

        val request = BaseAuthenticationRequest(
            requestFactory.post(url.toString(), credentialsAdapter, dPoP), clientId, baseURL
        ).apply {
            addParameters(parameters)
            addValidator(object : RequestValidator {
                override fun validate(options: RequestOptions) {
                    requireNotBlank(otp, ONE_TIME_PASSWORD_KEY)
                }
            })
        }
        return request
    }

    private fun challengeRequest(
        parameters: Map<String, String>
    ): Request<PasswordlessChallenge, AuthenticationException> {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(OTP_PATH)
            .addPathSegment(CHALLENGE_PATH)
            .build()

        val challengeAdapter: JsonAdapter<PasswordlessChallenge> =
            GsonAdapter(PasswordlessChallenge::class.java, gson)

        return requestFactory.post(url.toString(), challengeAdapter)
            .addParameters(parameters)
    }

    private fun requireNotBlank(value: String, name: String) {
        if (value.isBlank()) {
            throw AuthenticationException(INVALID_REQUEST, "$name is required")
        }
    }

    private fun createErrorAdapter(): ErrorAdapter<AuthenticationException> {
        val mapAdapter = GsonAdapter.forMap(gson)
        return object : ErrorAdapter<AuthenticationException> {
            override fun fromRawResponse(
                statusCode: Int, bodyText: String, headers: Map<String, List<String>>
            ): AuthenticationException = AuthenticationException(bodyText, statusCode)

            @Throws(IOException::class)
            override fun fromJsonResponse(
                statusCode: Int,
                reader: Reader
            ): AuthenticationException {
                val values = mapAdapter.fromJson(reader)
                return AuthenticationException(values, statusCode)
            }

            override fun fromException(cause: Throwable): AuthenticationException {
                if (isNetworkError(cause)) {
                    return AuthenticationException(
                        "Failed to execute the network request", NetworkErrorException(cause)
                    )
                }
                if (cause is DPoPException) {
                    return AuthenticationException(
                        cause.message ?: "Error while attaching DPoP proof", cause
                    )
                }
                return AuthenticationException(
                    "Something went wrong", Auth0Exception("Something went wrong", cause)
                )
            }
        }
    }

    private companion object {
        private const val OTP_PATH = "otp"
        private const val CHALLENGE_PATH = "challenge"
        private const val OAUTH_PATH = "oauth"
        private const val TOKEN_PATH = "token"
        private const val EMAIL_KEY = "email"
        private const val PHONE_NUMBER_KEY = "phone_number"
        private const val DELIVERY_METHOD_KEY = "delivery_method"
        private const val ALLOW_SIGNUP_KEY = "allow_signup"
        private const val CONNECTION_KEY = "connection"
        private const val AUTH_SESSION_KEY = "auth_session"
        private const val ONE_TIME_PASSWORD_KEY = "otp"
        private const val INVALID_REQUEST = "invalid_request"
    }
}
