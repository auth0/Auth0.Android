package com.auth0.android.authentication.mfa

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.authentication.mfa.MfaException.MfaChallengeException
import com.auth0.android.authentication.mfa.MfaException.MfaEnrollmentException
import com.auth0.android.authentication.mfa.MfaException.MfaListAuthenticatorsException
import com.auth0.android.authentication.mfa.MfaException.MfaVerifyException
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.Request
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.RequestValidator
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.auth0.android.result.Authenticator
import com.auth0.android.result.Challenge
import com.auth0.android.result.Credentials
import com.auth0.android.result.EnrollmentChallenge
import com.google.gson.Gson
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader

/**
 * API client for handling Multi-Factor Authentication (MFA) flows.
 *
 * This client provides methods to handle MFA challenges and enrollments following
 * the Auth0 MFA API. It is typically obtained from [com.auth0.android.authentication.AuthenticationAPIClient.mfaClient]
 * after receiving an `mfa_required` error during authentication.
 *
 * ## Usage
 *
 * ```kotlin
 * val authClient = AuthenticationAPIClient(auth0)
 * try {
 *     val credentials = authClient.login("user@example.com", "password").await()
 * } catch (error: AuthenticationException) {
 *     if (error.isMultifactorRequired) {
 *         val mfaPayload = error.mfaRequiredErrorPayload
 *         if (mfaPayload != null) {
 *             val mfaClient = authClient.mfaClient(mfaPayload.mfaToken)
 *             // Use mfaClient to handle MFA flow
 *         }
 *     }
 * }
 * ```
 *
 * @see com.auth0.android.authentication.AuthenticationAPIClient.mfaClient
 * @see [MFA API Documentation](https://auth0.com/docs/api/authentication#multi-factor-authentication)
 */
public class MfaApiClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val mfaToken: String,
    private val gson: Gson
) {

    // Specialized factories for MFA-specific errors
    private val listAuthenticatorsFactory: RequestFactory<MfaListAuthenticatorsException> by lazy {
        RequestFactory(auth0.networkingClient, createListAuthenticatorsErrorAdapter()).apply {
            setAuth0ClientInfo(auth0.auth0UserAgent.value)
        }
    }

    private val enrollmentFactory: RequestFactory<MfaEnrollmentException> by lazy {
        RequestFactory(auth0.networkingClient, createEnrollmentErrorAdapter()).apply {
            setAuth0ClientInfo(auth0.auth0UserAgent.value)
        }
    }

    private val challengeFactory: RequestFactory<MfaChallengeException> by lazy {
        RequestFactory(auth0.networkingClient, createChallengeErrorAdapter()).apply {
            setAuth0ClientInfo(auth0.auth0UserAgent.value)
        }
    }

    private val verifyFactory: RequestFactory<MfaVerifyException> by lazy {
        RequestFactory(auth0.networkingClient, createVerifyErrorAdapter()).apply {
            setAuth0ClientInfo(auth0.auth0UserAgent.value)
        }
    }

    /**
     * Creates a new MfaApiClient instance.
     *
     * @param auth0 the Auth0 account information
     * @param mfaToken the MFA token received from the mfa_required error
     */
    public constructor(auth0: Auth0, mfaToken: String) : this(
        auth0,
        mfaToken,
        GsonProvider.gson
    )

    private val clientId: String = auth0.clientId
    private val baseURL: String = auth0.getDomainUrl()

    /**
     * Retrieves the list of available authenticators for the user, filtered by the specified factor types.
     *
     * This endpoint returns all available authenticators that the user can use for MFA,
     * filtered by the specified factor types. The filtering is performed by the SDK after
     * receiving the response from the API.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.getAuthenticators(listOf("otp", "oob"))
     *     .start(object : Callback<List<Authenticator>, MfaListAuthenticatorsException> {
     *         override fun onSuccess(result: List<Authenticator>) {
     *             // Only OTP and OOB authenticators returned
     *         }
     *         override fun onFailure(error: MfaListAuthenticatorsException) { }
     *     })
     * ```
     *
     * @param factorsAllowed Array of factor types to filter the authenticators (e.g., `["otp", "oob", "recovery-code"]`).
     *                       Must contain at least one factor type.
     * @return a request to configure and start that will yield a list of [Authenticator]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#list-authenticators)
     */
    public fun getAuthenticators(
        factorsAllowed: List<String>
    ): Request<List<Authenticator>, MfaListAuthenticatorsException> {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(MFA_PATH)
            .addPathSegment(AUTHENTICATORS_PATH)
            .build()

        val authenticatorsAdapter = createFilteringAuthenticatorsAdapter(factorsAllowed)

        val request = listAuthenticatorsFactory.get(url.toString(), authenticatorsAdapter)
            .addHeader(HEADER_AUTHORIZATION, "Bearer $mfaToken")

        request.addValidator(object : RequestValidator {
            override fun validate(options: RequestOptions) {
                if (factorsAllowed.isEmpty()) {
                    throw MfaListAuthenticatorsException.invalidRequest(
                        "factorsAllowed is required and must contain at least one factor type."
                    )
                }
            }
        })

        return request
    }

    /**
     * Enrolls a new MFA factor for the user.
     *
     * This method initiates the enrollment of a new MFA factor based on the specified enrollment type.
     * The response contains the information needed to complete the enrollment process.
     *
     * ## Usage
     *
     * ```kotlin
     * // Phone (SMS) enrollment
     * mfaClient.enroll(MfaEnrollmentType.Phone("+12025550135"))
     *     .start(object : Callback<EnrollmentChallenge, MfaEnrollmentException> {
     *         override fun onSuccess(result: EnrollmentChallenge) {
     *             println("Enrollment initiated: ${result.oobCode}")
     *         }
     *         override fun onFailure(error: MfaEnrollmentException) { }
     *     })
     *
     * // Email enrollment
     * mfaClient.enroll(MfaEnrollmentType.Email("user@example.com"))
     *
     * // TOTP (Authenticator app) enrollment
     * mfaClient.enroll(MfaEnrollmentType.Otp)
     *
     * // Push notification enrollment
     * mfaClient.enroll(MfaEnrollmentType.Push)
     * ```
     *
     * @param type The type of MFA enrollment to perform.
     * @return a request to configure and start that will yield [EnrollmentChallenge]
     *
     * @see MfaEnrollmentType
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#enroll-authenticator)
     */
    public fun enroll(type: MfaEnrollmentType): Request<EnrollmentChallenge, MfaEnrollmentException> {
        return when (type) {
            is MfaEnrollmentType.Phone -> enrollOob(
                oobChannel = "sms",
                phoneNumber = type.phoneNumber
            )

            is MfaEnrollmentType.Email -> enrollOob(oobChannel = "email", email = type.email)
            is MfaEnrollmentType.Otp -> enrollOtpInternal()
            is MfaEnrollmentType.Push -> enrollOob(oobChannel = "auth0")
        }
    }


    /**
     * Initiates an MFA challenge for an enrolled authenticator.
     *
     * This method requests a challenge (e.g., OTP code via SMS) for an already enrolled MFA factor.
     * The user must complete the challenge to authenticate successfully.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.challenge("sms|dev_authenticator_id")
     *     .start(object : Callback<Challenge, MfaChallengeException> {
     *         override fun onSuccess(result: Challenge) {
     *             println("Challenge sent: ${result.oobCode}")
     *         }
     *         override fun onFailure(error: MfaChallengeException) { }
     *     })
     * ```
     *
     * @param authenticatorId The ID of the enrolled authenticator.
     * @return a request to configure and start that will yield [Challenge]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#challenge-with-sms-oob-otp)
     */
    public fun challenge(authenticatorId: String): Request<Challenge, MfaChallengeException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(CHALLENGE_TYPE_KEY, "oob")
            .set(AUTHENTICATOR_ID_KEY, authenticatorId)
            .asDictionary()

        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(MFA_PATH)
            .addPathSegment(CHALLENGE_PATH)
            .build()

        val challengeAdapter: JsonAdapter<Challenge> = GsonAdapter(
            Challenge::class.java, gson
        )

        return challengeFactory.post(url.toString(), challengeAdapter)
            .addParameters(parameters)
    }


    /**
     * Verifies an MFA challenge using the specified verification type.
     *
     * This method completes the MFA authentication flow by verifying the user's credentials
     * based on the verification type. Upon successful verification, user credentials are returned.
     *
     * ## Usage
     *
     * ```kotlin
     * // Verify with OOB code (SMS/Email)
     * mfaClient.verify(MfaVerificationType.Oob(oobCode = "Fe26.2*...", bindingCode = "123456"))
     *     .start(object : Callback<Credentials, MfaVerifyException> {
     *         override fun onSuccess(result: Credentials) {
     *             println("Obtained credentials: ${result.accessToken}")
     *         }
     *         override fun onFailure(error: MfaVerifyException) { }
     *     })
     *
     * // Verify with OTP code (Authenticator app)
     * mfaClient.verify(MfaVerificationType.Otp(otp = "123456"))
     *
     * // Verify with recovery code
     * mfaClient.verify(MfaVerificationType.RecoveryCode(code = "RECOVERY_CODE_123"))
     * ```
     *
     * @param type The type of MFA verification to perform.
     * @return a request to configure and start that will yield [Credentials]
     *
     * @see MfaVerificationType
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#verify-with-mfa)
     */
    public fun verify(type: MfaVerificationType): Request<Credentials, MfaVerifyException> {
        return when (type) {
            is MfaVerificationType.Oob -> verifyOobInternal(type.oobCode, type.bindingCode)
            is MfaVerificationType.Otp -> verifyOtpInternal(type.otp)
            is MfaVerificationType.RecoveryCode -> verifyRecoveryCodeInternal(type.code)
        }
    }

    // ========== Private Helper Methods ==========

    /**
     * Creates a JSON adapter that filters authenticators based on allowed factor types.
     *
     * This processing is performed internally by the SDK after receiving the API response.
     * The client only specifies which factor types are allowed; all filtering logic is handled
     * transparently by the SDK.
     *
     * **Filtering:**
     * Authenticators are filtered by their effective type:
     * - OOB authenticators: matched by their channel ("sms" or "email")
     * - Other authenticators: matched by their type ("otp", "recovery-code", etc.)
     *
     * @param factorsAllowed List of factor types to include (e.g., ["sms", "email", "otp"])
     * @return A JsonAdapter that produces a filtered list of authenticators
     */
    private fun createFilteringAuthenticatorsAdapter(factorsAllowed: List<String>): JsonAdapter<List<Authenticator>> {
        val baseAdapter = GsonAdapter.forListOf(Authenticator::class.java, gson)
        return object : JsonAdapter<List<Authenticator>> {
            override fun fromJson(reader: Reader, metadata: Map<String, Any>): List<Authenticator> {
                val allAuthenticators = baseAdapter.fromJson(reader, metadata)

                return allAuthenticators.filter { authenticator ->
                    matchesFactorType(authenticator, factorsAllowed)
                }
            }
        }
    }

    /**
     * Checks if an authenticator matches any of the allowed factor types.
     *
     * The matching logic handles various factor type aliases:
     * - "sms" or "phone": matches OOB authenticators with SMS channel
     * - "email": matches OOB authenticators with email channel
     * - "otp" or "totp": matches time-based one-time password authenticators
     * - "oob": matches any out-of-band authenticator regardless of channel
     * - "recovery-code": matches recovery code authenticators
     * - "push-notification": matches push notification authenticators
     *
     * @param authenticator The authenticator to check
     * @param factorsAllowed List of allowed factor types
     * @return true if the authenticator matches any allowed factor type
     */
    private fun matchesFactorType(
        authenticator: Authenticator,
        factorsAllowed: List<String>
    ): Boolean {
        val effectiveType = getEffectiveType(authenticator)

        return factorsAllowed.any { factor ->
            val normalizedFactor = factor.lowercase(java.util.Locale.ROOT)
            when (normalizedFactor) {
                "sms", "phone" -> effectiveType == "sms" || effectiveType == "phone"
                "email" -> effectiveType == "email"
                "otp", "totp" -> effectiveType == "otp" || effectiveType == "totp"
                "oob" -> authenticator.authenticatorType == "oob" || authenticator.type == "oob"
                "recovery-code" -> effectiveType == "recovery-code"
                "push-notification" -> effectiveType == "push-notification"
                else -> effectiveType == normalizedFactor ||
                        authenticator.authenticatorType?.lowercase(java.util.Locale.ROOT) == normalizedFactor ||
                        authenticator.type.lowercase(java.util.Locale.ROOT) == normalizedFactor
            }
        }
    }

    /**
     * Resolves the effective type of an authenticator for filtering purposes.
     *
     * OOB (out-of-band) authenticators use their channel ("sms" or "email") as the
     * effective type, since users typically filter by delivery method rather than
     * the generic "oob" type. Other authenticators use their authenticatorType directly.
     *
     * @param authenticator The authenticator to get the type for
     * @return The effective type string used for filtering
     */
    private fun getEffectiveType(authenticator: Authenticator): String {
        return when (authenticator.authenticatorType) {
            "oob" -> authenticator.oobChannel ?: "oob"
            else -> authenticator.authenticatorType ?: authenticator.type
        }
    }

    /**
     * Helper function for OOB enrollment (SMS, email, push).
     */
    private fun enrollOob(
        oobChannel: String,
        phoneNumber: String? = null,
        email: String? = null
    ): Request<EnrollmentChallenge, MfaEnrollmentException> {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(MFA_PATH)
            .addPathSegment(ASSOCIATE_PATH)
            .build()

        val enrollmentAdapter: JsonAdapter<EnrollmentChallenge> = GsonAdapter(
            EnrollmentChallenge::class.java, gson
        )

        val request = enrollmentFactory.post(url.toString(), enrollmentAdapter)
            .addHeader(HEADER_AUTHORIZATION, "Bearer $mfaToken")
            .addParameter(AUTHENTICATOR_TYPES_KEY, listOf("oob"))
            .addParameter(OOB_CHANNELS_KEY, listOf(oobChannel))

        if (phoneNumber != null) {
            request.addParameter(PHONE_NUMBER_KEY, phoneNumber)
        }
        if (email != null) {
            request.addParameter(EMAIL_KEY, email)
        }

        return request
    }

    /**
     * Internal helper for OTP enrollment.
     */
    private fun enrollOtpInternal(): Request<EnrollmentChallenge, MfaEnrollmentException> {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(MFA_PATH)
            .addPathSegment(ASSOCIATE_PATH)
            .build()

        val enrollmentAdapter: JsonAdapter<EnrollmentChallenge> = GsonAdapter(
            EnrollmentChallenge::class.java, gson
        )

        return enrollmentFactory.post(url.toString(), enrollmentAdapter)
            .addHeader(HEADER_AUTHORIZATION, "Bearer $mfaToken")
            .addParameter(AUTHENTICATOR_TYPES_KEY, listOf("otp"))
    }

    /**
     * Internal helper for OOB verification.
     */
    private fun verifyOobInternal(
        oobCode: String,
        bindingCode: String? = null
    ): Request<Credentials, MfaVerifyException> {
        val parametersBuilder = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(GRANT_TYPE_MFA_OOB)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(OUT_OF_BAND_CODE_KEY, oobCode)

        if (bindingCode != null) {
            parametersBuilder.set(BINDING_CODE_KEY, bindingCode)
        }

        return tokenRequest(parametersBuilder.asDictionary())
    }

    /**
     * Internal helper for OTP verification.
     */
    private fun verifyOtpInternal(otp: String): Request<Credentials, MfaVerifyException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(GRANT_TYPE_MFA_OTP)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(ONE_TIME_PASSWORD_KEY, otp)
            .asDictionary()

        return tokenRequest(parameters)
    }

    /**
     * Internal helper for recovery code verification.
     */
    private fun verifyRecoveryCodeInternal(recoveryCode: String): Request<Credentials, MfaVerifyException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(GRANT_TYPE_MFA_RECOVERY_CODE)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(RECOVERY_CODE_KEY, recoveryCode)
            .asDictionary()

        return tokenRequest(parameters)
    }

    /**
     * Helper function to make a request to the /oauth/token endpoint.
     */
    private fun tokenRequest(parameters: Map<String, String>): Request<Credentials, MfaVerifyException> {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()

        val credentialsAdapter: JsonAdapter<Credentials> = GsonAdapter(
            Credentials::class.java, gson
        )

        return verifyFactory.post(url.toString(), credentialsAdapter)
            .addParameters(parameters)
    }


    /**
     * Creates error adapter for getAuthenticators() operations.
     */
    private fun createListAuthenticatorsErrorAdapter(): ErrorAdapter<MfaListAuthenticatorsException> {
        val mapAdapter = GsonAdapter.forMap(gson)
        return object : ErrorAdapter<MfaListAuthenticatorsException> {
            override fun fromRawResponse(
                statusCode: Int, bodyText: String, headers: Map<String, List<String>>
            ): MfaListAuthenticatorsException {
                val values = mapOf("error_description" to bodyText)
                return MfaListAuthenticatorsException(values, statusCode)
            }

            @Throws(IOException::class)
            override fun fromJsonResponse(
                statusCode: Int, reader: Reader
            ): MfaListAuthenticatorsException {
                val values = mapAdapter.fromJson(reader)
                return MfaListAuthenticatorsException(values, statusCode)
            }

            override fun fromException(cause: Throwable): MfaListAuthenticatorsException {
                return if (isNetworkError(cause)) {
                    MfaListAuthenticatorsException(
                        code = "network_error",
                        description = "Failed to execute the network request",
                        cause = cause
                    )
                } else {
                    MfaListAuthenticatorsException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong",
                        cause = cause
                    )
                }
            }
        }
    }

    /**
     * Creates error adapter for enroll() operations.
     */
    private fun createEnrollmentErrorAdapter(): ErrorAdapter<MfaEnrollmentException> {
        val mapAdapter = GsonAdapter.forMap(gson)
        return object : ErrorAdapter<MfaEnrollmentException> {
            override fun fromRawResponse(
                statusCode: Int, bodyText: String, headers: Map<String, List<String>>
            ): MfaEnrollmentException {
                val values = mapOf("error_description" to bodyText)
                return MfaEnrollmentException(values, statusCode)
            }

            @Throws(IOException::class)
            override fun fromJsonResponse(
                statusCode: Int, reader: Reader
            ): MfaEnrollmentException {
                val values = mapAdapter.fromJson(reader)
                return MfaEnrollmentException(values, statusCode)
            }

            override fun fromException(cause: Throwable): MfaEnrollmentException {
                return if (isNetworkError(cause)) {
                    MfaEnrollmentException(
                        code = "network_error",
                        description = "Failed to execute the network request",
                        cause = cause
                    )
                } else {
                    MfaEnrollmentException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong",
                        cause = cause
                    )
                }
            }
        }
    }

    /**
     * Creates error adapter for challenge() operations.
     */
    private fun createChallengeErrorAdapter(): ErrorAdapter<MfaChallengeException> {
        val mapAdapter = GsonAdapter.forMap(gson)
        return object : ErrorAdapter<MfaChallengeException> {
            override fun fromRawResponse(
                statusCode: Int, bodyText: String, headers: Map<String, List<String>>
            ): MfaChallengeException {
                val values = mapOf("error_description" to bodyText)
                return MfaChallengeException(values, statusCode)
            }

            @Throws(IOException::class)
            override fun fromJsonResponse(
                statusCode: Int, reader: Reader
            ): MfaChallengeException {
                val values = mapAdapter.fromJson(reader)
                return MfaChallengeException(values, statusCode)
            }

            override fun fromException(cause: Throwable): MfaChallengeException {
                return if (isNetworkError(cause)) {
                    MfaChallengeException(
                        code = "network_error",
                        description = "Failed to execute the network request",
                        cause = cause
                    )
                } else {
                    MfaChallengeException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong",
                        cause = cause
                    )
                }
            }
        }
    }

    /**
     * Creates error adapter for verify() operations.
     */
    private fun createVerifyErrorAdapter(): ErrorAdapter<MfaVerifyException> {
        val mapAdapter = GsonAdapter.forMap(gson)
        return object : ErrorAdapter<MfaVerifyException> {
            override fun fromRawResponse(
                statusCode: Int, bodyText: String, headers: Map<String, List<String>>
            ): MfaVerifyException {
                val values = mapOf("error_description" to bodyText)
                return MfaVerifyException(values, statusCode)
            }

            @Throws(IOException::class)
            override fun fromJsonResponse(
                statusCode: Int, reader: Reader
            ): MfaVerifyException {
                val values = mapAdapter.fromJson(reader)
                return MfaVerifyException(values, statusCode)
            }

            override fun fromException(cause: Throwable): MfaVerifyException {
                return if (isNetworkError(cause)) {
                    MfaVerifyException(
                        code = "network_error",
                        description = "Failed to execute the network request",
                        cause = cause
                    )
                } else {
                    MfaVerifyException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong",
                        cause = cause
                    )
                }
            }
        }
    }

    private companion object {
        private const val MFA_PATH = "mfa"
        private const val AUTHENTICATORS_PATH = "authenticators"
        private const val CHALLENGE_PATH = "challenge"
        private const val ASSOCIATE_PATH = "associate"
        private const val OAUTH_PATH = "oauth"
        private const val TOKEN_PATH = "token"
        private const val HEADER_AUTHORIZATION = "Authorization"
        private const val MFA_TOKEN_KEY = "mfa_token"
        private const val CHALLENGE_TYPE_KEY = "challenge_type"
        private const val AUTHENTICATOR_ID_KEY = "authenticator_id"
        private const val AUTHENTICATOR_TYPES_KEY = "authenticator_types"
        private const val OOB_CHANNELS_KEY = "oob_channels"
        private const val PHONE_NUMBER_KEY = "phone_number"
        private const val EMAIL_KEY = "email"
        private const val ONE_TIME_PASSWORD_KEY = "otp"
        private const val OUT_OF_BAND_CODE_KEY = "oob_code"
        private const val BINDING_CODE_KEY = "binding_code"
        private const val RECOVERY_CODE_KEY = "recovery_code"
        private const val GRANT_TYPE_MFA_OTP = "http://auth0.com/oauth/grant-type/mfa-otp"
        private const val GRANT_TYPE_MFA_OOB = "http://auth0.com/oauth/grant-type/mfa-oob"
        private const val GRANT_TYPE_MFA_RECOVERY_CODE =
            "http://auth0.com/oauth/grant-type/mfa-recovery-code"
    }
}
