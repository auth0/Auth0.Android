package com.auth0.android.authentication.passwordless

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.Request
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
 * API client for the database-connection OTP (passwordless) authentication flow.
 *
 * This client drives a two-step flow against a database connection that has `email_otp` or
 * `phone_otp` enabled:
 *
 * 1. Issue a one-time code with [challengeWithEmail] or [challengeWithPhoneNumber]. Both return an
 *    opaque [PasswordlessChallenge] containing an `auth_session` token.
 * 2. Exchange that session and the code the user received for [Credentials] with [loginWithOTP].
 *
 * Obtain an instance from
 * [com.auth0.android.authentication.AuthenticationAPIClient.passwordlessClient].
 *
 * ## Usage
 *
 * ```kotlin
 * val passwordless = AuthenticationAPIClient(auth0).passwordlessClient()
 *
 * // Step 1 — issue the challenge
 * passwordless.challengeWithEmail("user@example.com", "Username-Password-Authentication")
 *     .start(object : Callback<PasswordlessChallenge, AuthenticationException> {
 *         override fun onSuccess(result: PasswordlessChallenge) {
 *             val authSession = result.authSession // store it, then prompt for the code
 *         }
 *         override fun onFailure(error: AuthenticationException) { }
 *     })
 *
 * // Step 2 — exchange the code for credentials
 * passwordless.loginWithOTP(authSession, "123456")
 *     .start(object : Callback<Credentials, AuthenticationException> {
 *         override fun onSuccess(result: Credentials) { }
 *         override fun onFailure(error: AuthenticationException) { }
 *     })
 * ```
 *
 * @see com.auth0.android.authentication.AuthenticationAPIClient.passwordlessClient
 * @see [OTP Challenge endpoint](https://auth0.com/docs/api/authentication)
 */
public class PasswordlessClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val gson: Gson
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
    public constructor(auth0: Auth0) : this(auth0, GsonProvider.gson)

    private val clientId: String = auth0.clientId
    private val baseURL: String = auth0.getDomainUrl()

    /**
     * Issues an OTP challenge to an email address for a database connection.
     *
     * Sends a one-time code to the given email for a connection that has `email_otp` enabled.
     * For privacy, the server **always responds successfully regardless of whether the user
     * exists** (user-enumeration prevention); a successful response therefore does not confirm
     * that an account exists. On success an opaque [PasswordlessChallenge.authSession] is returned — pass
     * it to [loginWithOTP] together with the code the user receives.
     *
     * ## Usage
     *
     * ```kotlin
     * passwordlessClient.challengeWithEmail("user@example.com", "Username-Password-Authentication")
     *     .start(object : Callback<PasswordlessChallenge, AuthenticationException> {
     *         override fun onSuccess(result: PasswordlessChallenge) { }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param email the email address to send the one-time code to.
     * @param connection the name of the database connection; it must have `email_otp` enabled.
     * @param allowSignup whether to allow sign-up if the user does not yet exist. Defaults to `false`.
     * @return a request that, when started, yields an [PasswordlessChallenge] containing the `auth_session`.
     *         On failure it yields a [AuthenticationException] whose [AuthenticationException.getCode]
     *         is one of `invalid_request`, `invalid_connection` (400), `invalid_client` (401),
     *         `unauthorized_client` (403), `endpoint_disabled` (404), or `too_many_requests` (429).
     * @see loginWithOTP
     */
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
        return challengeRequest(parameters)
    }

    /**
     * Issues an OTP challenge to a phone number for a database connection.
     *
     * Sends a one-time code to the given phone number for a connection that has `phone_otp`
     * enabled, delivered either by SMS or voice call per [deliveryMethod]. For privacy, the server
     * **always responds successfully regardless of whether the user exists** (user-enumeration
     * prevention); a successful response therefore does not confirm that an account exists. On
     * success an opaque [PasswordlessChallenge.authSession] is returned — pass it to [loginWithOTP] together
     * with the code the user receives.
     *
     * ## Usage
     *
     * ```kotlin
     * passwordlessClient.challengeWithPhoneNumber(
     *     phoneNumber = "+15555550123",
     *     connection = "Username-Password-Authentication",
     *     deliveryMethod = DeliveryMethod.TEXT
     * ).start(object : Callback<PasswordlessChallenge, AuthenticationException> {
     *     override fun onSuccess(result: PasswordlessChallenge) { }
     *     override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param phoneNumber the E.164 phone number to send the one-time code to (e.g. `"+15555550123"`).
     * @param connection the name of the database connection; it must have `phone_otp` enabled.
     * @param deliveryMethod how to deliver the code — [DeliveryMethod.TEXT] (SMS) or
     *        [DeliveryMethod.VOICE]. Defaults to [DeliveryMethod.TEXT].
     * @param allowSignup whether to allow sign-up if the user does not yet exist. Defaults to `false`.
     * @return a request that, when started, yields an [PasswordlessChallenge] containing the `auth_session`.
     *         On failure it yields a [AuthenticationException] whose [AuthenticationException.getCode]
     *         is one of `invalid_request`, `invalid_connection` (400), `invalid_client` (401),
     *         `unauthorized_client` (403), `endpoint_disabled` (404), or `too_many_requests` (429).
     * @see loginWithOTP
     */
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
        return challengeRequest(parameters)
    }

    /**
     * Completes the OTP flow by verifying the one-time code and obtaining credentials.
     *
     * Exchanges the opaque `auth_session` returned by [challengeWithEmail] or
     * [challengeWithPhoneNumber], together with the code the user received, for [Credentials] using
     * the passwordless OTP grant on `POST /oauth/token`.
     *
     * ## Usage
     *
     * ```kotlin
     * passwordlessClient.loginWithOTP(authSession, "123456")
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param authSession the opaque session token from a prior challenge (see [PasswordlessChallenge.authSession]).
     * @param otp the one-time code the user received via email, SMS, or voice call.
     * @return a request that, when started, yields [Credentials] on success, or a
     *         [AuthenticationException] (e.g. `invalid_grant` for an incorrect or expired code) on failure.
     * @see challengeWithEmail
     * @see challengeWithPhoneNumber
     */
    public fun loginWithOTP(
        authSession: String,
        otp: String
    ): Request<Credentials, AuthenticationException> {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()

        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
            .set(AUTH_SESSION_KEY, authSession)
            .set(ONE_TIME_PASSWORD_KEY, otp)
            .asDictionary()

        val credentialsAdapter: JsonAdapter<Credentials> =
            GsonAdapter(Credentials::class.java, gson)

        return requestFactory.post(url.toString(), credentialsAdapter)
            .addParameters(parameters)
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

    private fun createErrorAdapter(): ErrorAdapter<AuthenticationException> {
        val mapAdapter = GsonAdapter.forMap(gson)
        return object : ErrorAdapter<AuthenticationException> {
            override fun fromRawResponse(
                statusCode: Int, bodyText: String, headers: Map<String, List<String>>
            ): AuthenticationException {
                return AuthenticationException(bodyText, statusCode)
            }

            @Throws(IOException::class)
            override fun fromJsonResponse(
                statusCode: Int,
                reader: Reader
            ): AuthenticationException {
                val values = mapAdapter.fromJson(reader)
                return AuthenticationException(values, statusCode)
            }

            override fun fromException(cause: Throwable): AuthenticationException {
                return if (isNetworkError(cause)) {
                    AuthenticationException(
                        "Failed to execute the network request", NetworkErrorException(cause)
                    )
                } else {
                    AuthenticationException(
                        "Something went wrong", Auth0Exception("Something went wrong", cause)
                    )
                }
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
        private const val AUTH_SESSION_KEY = "auth_session"
        private const val ONE_TIME_PASSWORD_KEY = "otp"
    }
}
