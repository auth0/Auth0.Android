package com.auth0.android.authentication

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.MfaException.*
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
 * the Auth0 MFA API. It is typically obtained from [AuthenticationAPIClient.mfaClient]
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
 * @see AuthenticationAPIClient.mfaClient
 * @see [MFA API Documentation](https://auth0.com/docs/api/authentication#multi-factor-authentication)
 */
public class MfaApiClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val mfaToken: String,
    private val gson: Gson
) {

    // Specialized factories for MFA-specific errors
    private val listAuthenticatorsFactory: RequestFactory<MfaListAuthenticatorsException> by lazy {
        RequestFactory(auth0.networkingClient, createListAuthenticatorsErrorAdapter())
    }

    private val enrollmentFactory: RequestFactory<MfaEnrollmentException> by lazy {
        RequestFactory(auth0.networkingClient, createEnrollmentErrorAdapter())
    }

    private val challengeFactory: RequestFactory<MfaChallengeException> by lazy {
        RequestFactory(auth0.networkingClient, createChallengeErrorAdapter())
    }

    private val verifyFactory: RequestFactory<MfaVerifyException> by lazy {
        RequestFactory(auth0.networkingClient, createVerifyErrorAdapter())
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

    private val clientId: String
        get() = auth0.clientId
    private val baseURL: String
        get() = auth0.getDomainUrl()

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
                        "factorsAllowed is required and must contain at least one challenge type."
                    )
                }
            }
        })

        return request
    }

    /**
     * Creates a JSON adapter that filters and deduplicates authenticators based on allowed factor types.
     *
     * This processing is performed internally by the SDK after receiving the API response.
     * The client only specifies which factor types are allowed; all filtering and deduplication
     * logic is handled transparently by the SDK.
     *
     * **Filtering:**
     * Authenticators are filtered by their effective type:
     * - OOB authenticators: matched by their channel ("sms" or "email")
     * - Other authenticators: matched by their type ("otp", "recovery-code", etc.)
     *
     * **Deduplication:**
     * Multiple enrollments of the same phone number or email are consolidated:
     * - Active authenticators are preferred over inactive ones
     * - Among authenticators with the same status, the most recently created is kept
     *
     * @param factorsAllowed List of factor types to include (e.g., ["sms", "email", "otp"])
     * @return A JsonAdapter that produces a filtered and deduplicated list of authenticators
     */
    private fun createFilteringAuthenticatorsAdapter(factorsAllowed: List<String>): JsonAdapter<List<Authenticator>> {
        val baseAdapter = GsonAdapter.forListOf(Authenticator::class.java, gson)
        return object : JsonAdapter<List<Authenticator>> {
            override fun fromJson(reader: Reader, metadata: Map<String, Any>): List<Authenticator> {
                val allAuthenticators = baseAdapter.fromJson(reader, metadata)
                
                val filtered = allAuthenticators.filter { authenticator ->
                    matchesFactorType(authenticator, factorsAllowed)
                }
                
                return deduplicateAuthenticators(filtered)
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
    private fun matchesFactorType(authenticator: Authenticator, factorsAllowed: List<String>): Boolean {
        val effectiveType = getEffectiveType(authenticator)
        
        return factorsAllowed.any { factor ->
            when (factor.lowercase(java.util.Locale.ROOT)) {
                "sms", "phone" -> effectiveType == "sms" || effectiveType == "phone"
                "email" -> effectiveType == "email"
                "otp", "totp" -> effectiveType == "otp" || effectiveType == "totp"
                "oob" -> authenticator.authenticatorType == "oob"
                "recovery-code" -> effectiveType == "recovery-code"
                "push-notification" -> effectiveType == "push-notification"
                else -> effectiveType == factor || authenticator.authenticatorType == factor
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
            else -> authenticator.authenticatorType ?: authenticator.type ?: ""
        }
    }

    /**
     * Removes duplicate authenticators to return only the most relevant enrollment per identity.
     *
     * Users may have multiple enrollments for the same phone number or email address
     * (e.g., from re-enrolling after failed attempts). This method consolidates them
     * to present a clean list:
     *
     * **Grouping strategy:**
     * - SMS/Email (OOB): grouped by channel + name (e.g., all "+1234567890" SMS entries)
     * - TOTP: each authenticator is unique (different authenticator apps)
     * - Recovery code: only one per user
     *
     * **Selection criteria (in order of priority):**
     * 1. Active authenticators are preferred over inactive ones
     * 2. Among same status, the most recently created is selected
     *
     * @param authenticators The list of authenticators to deduplicate
     * @return A deduplicated list with one authenticator per unique identity
     */
    private fun deduplicateAuthenticators(authenticators: List<Authenticator>): List<Authenticator> {
        val grouped = authenticators.groupBy { authenticator ->
            when (authenticator.authenticatorType) {
                "oob" -> {
                    val channel = authenticator.oobChannel ?: "unknown"
                    val name = authenticator.name ?: authenticator.id
                    "$channel:$name"
                }
                "otp" -> {
                    authenticator.id
                }
                "recovery-code" -> {
                    "recovery-code"
                }
                else -> {
                    authenticator.id
                }
            }
        }

        return grouped.values.map { group ->
            group.sortedWith(
                compareByDescending<Authenticator> { it.active }
                    .thenByDescending { it.createdAt ?: "" }
            ).first()
        }
    }

    /**
     * Enrolls a phone number for SMS-based MFA.
     *
     * This method initiates the enrollment of a phone number as an MFA factor. An SMS with a verification
     * code will be sent to the specified phone number.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.enrollPhone("+12025550135")
     *     .start(object : Callback<EnrollmentChallenge, MfaEnrollmentException> {
     *         override fun onSuccess(result: EnrollmentChallenge) {
     *             println("Enrollment initiated: ${result.oobCode}")
     *         }
     *         override fun onFailure(error: MfaEnrollmentException) { }
     *     })
     * ```
     *
     * @param phoneNumber The phone number to enroll, including country code (e.g., `+12025550135`).
     * @return a request to configure and start that will yield [EnrollmentChallenge]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#enroll-and-challenge-a-sms-or-voice-authenticator)
     */
    public fun enrollPhone(phoneNumber: String): Request<EnrollmentChallenge, MfaEnrollmentException> {
        return enrollOob(oobChannel = "sms", phoneNumber = phoneNumber)
    }


    /**
     * Enrolls an email address for email-based MFA.
     *
     * This method initiates the enrollment of an email address as an MFA factor. Verification codes
     * will be sent to the specified email address during authentication.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.enrollEmail("user@example.com")
     *     .start(object : Callback<EnrollmentChallenge, MfaEnrollmentException> {
     *         override fun onSuccess(result: EnrollmentChallenge) {
     *             println("Email enrollment initiated: ${result.oobCode}")
     *         }
     *         override fun onFailure(error: MfaEnrollmentException) { }
     *     })
     * ```
     *
     * @param email The email address to enroll for MFA.
     * @return a request to configure and start that will yield [EnrollmentChallenge]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#enroll-and-challenge-a-email-authenticator)
     */
    public fun enrollEmail(email: String): Request<EnrollmentChallenge, MfaEnrollmentException> {
        return enrollOob(oobChannel = "email", email = email)
    }


    /**
     * Enrolls a time-based one-time password (TOTP) authenticator for MFA.
     *
     * This method initiates the enrollment of an authenticator app (like Google Authenticator or Authy)
     * as an MFA factor. It returns a challenge containing a QR code and secret that can be scanned
     * by the authenticator app.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.enrollOtp()
     *     .start(object : Callback<EnrollmentChallenge, MfaEnrollmentException> {
     *         override fun onSuccess(result: EnrollmentChallenge) {
     *             println("QR Code URI: ${result.barcodeUri}")
     *             println("Secret: ${result.secret}")
     *         }
     *         override fun onFailure(error: MfaEnrollmentException) { }
     *     })
     * ```
     *
     * @return a request to configure and start that will yield [EnrollmentChallenge] containing QR code and secret.
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#enroll-and-challenge-a-otp-authenticator)
     */
    public fun enrollOtp(): Request<EnrollmentChallenge, MfaEnrollmentException> {
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
     * Enrolls push notification as an MFA factor.
     *
     * This method initiates the enrollment of Auth0 Guardian push notifications as an MFA factor.
     * Users will receive authentication requests via push notifications on their enrolled device.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.enrollPush()
     *     .start(object : Callback<EnrollmentChallenge, MfaEnrollmentException> {
     *         override fun onSuccess(result: EnrollmentChallenge) {
     *             println("Push enrollment challenge: ${result.oobCode}")
     *         }
     *         override fun onFailure(error: MfaEnrollmentException) { }
     *     })
     * ```
     *
     * @return a request to configure and start that will yield [EnrollmentChallenge]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#enroll-and-challenge-push-notifications)
     * @see [Auth0 Guardian](https://auth0.com/docs/secure/multi-factor-authentication/auth0-guardian)
     */
    public fun enrollPush(): Request<EnrollmentChallenge, MfaEnrollmentException> {
        return enrollOob(oobChannel = "auth0")
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
     * Verifies an out-of-band (OOB) MFA challenge using a code received via SMS or email.
     *
     * This method completes the MFA authentication flow by verifying the OTP code sent to the user's
     * phone or email. Upon successful verification, user credentials are returned.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.verifyOob(oobCode = "oob_code", bindingCode = "123456")
     *     .start(object : Callback<Credentials, MfaVerifyException> {
     *         override fun onSuccess(result: Credentials) {
     *             println("Obtained credentials: ${result.accessToken}")
     *         }
     *         override fun onFailure(error: MfaVerifyException) { }
     *     })
     * ```
     *
     * @param oobCode The out-of-band code from the challenge response.
     * @param bindingCode Optional binding code for additional security verification.
     * @return a request to configure and start that will yield [Credentials]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#verify-with-out-of-band-oob)
     */
    public fun verifyOob(
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
     * Verifies an MFA challenge using a one-time password (OTP) code.
     *
     * This method completes the MFA authentication flow by verifying the OTP code from the user's
     * authenticator app. Upon successful verification, user credentials are returned.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.verifyOtp("123456")
     *     .start(object : Callback<Credentials, MfaVerifyException> {
     *         override fun onSuccess(result: Credentials) {
     *             println("Obtained credentials: ${result.accessToken}")
     *         }
     *         override fun onFailure(error: MfaVerifyException) { }
     *     })
     * ```
     *
     * @param otp The 6-digit one-time password code from the authenticator app.
     * @return a request to configure and start that will yield [Credentials]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#verify-with-one-time-password-otp)
     */
    public fun verifyOtp(otp: String): Request<Credentials, MfaVerifyException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(GRANT_TYPE_MFA_OTP)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(ONE_TIME_PASSWORD_KEY, otp)
            .asDictionary()

        return tokenRequest(parameters)
    }



    /**
     * Verifies an MFA challenge using a recovery code.
     *
     * This method allows users to authenticate when they don't have access to their primary MFA factor.
     * Recovery codes are typically provided during MFA enrollment and should be stored securely.
     *
     * ## Usage
     *
     * ```kotlin
     * mfaClient.verifyRecoveryCode("RECOVERY_CODE_123")
     *     .start(object : Callback<Credentials, MfaVerifyException> {
     *         override fun onSuccess(result: Credentials) {
     *             println("Obtained credentials: ${result.accessToken}")
     *             // result.recoveryCode contains a NEW recovery code to replace the used one
     *         }
     *         override fun onFailure(error: MfaVerifyException) { }
     *     })
     * ```
     *
     * @param recoveryCode The recovery code provided during MFA enrollment.
     * @return a request to configure and start that will yield [Credentials]
     *
     * @see [Authentication API Endpoint](https://auth0.com/docs/api/authentication#verify-with-recovery-code)
     */
    public fun verifyRecoveryCode(recoveryCode: String): Request<Credentials, MfaVerifyException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(GRANT_TYPE_MFA_RECOVERY_CODE)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(RECOVERY_CODE_KEY, recoveryCode)
            .asDictionary()

        return tokenRequest(parameters)
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
                        description = "Failed to execute the network request"
                    )
                } else {
                    MfaListAuthenticatorsException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong"
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
                        description = "Failed to execute the network request"
                    )
                } else {
                    MfaEnrollmentException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong"
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
                        description = "Failed to execute the network request"
                    )
                } else {
                    MfaChallengeException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong"
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
                        description = "Failed to execute the network request"
                    )
                } else {
                    MfaVerifyException(
                        code = Auth0Exception.UNKNOWN_ERROR,
                        description = cause.message ?: "Something went wrong"
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
        private const val GRANT_TYPE_MFA_RECOVERY_CODE = "http://auth0.com/oauth/grant-type/mfa-recovery-code"
    }
}
