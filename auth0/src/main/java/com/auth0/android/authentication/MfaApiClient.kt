package com.auth0.android.authentication

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.authentication.MfaException.*
import com.auth0.android.dpop.DPoPException
import com.auth0.android.request.AuthenticationRequest
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.Request
import com.auth0.android.request.internal.BaseAuthenticationRequest
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
 * This client is created via [AuthenticationAPIClient.mfa] and provides methods
 * to handle MFA challenges and enrollments.
 *
 * Example usage:
 * ```
 * val authClient = AuthenticationAPIClient(auth0)
 * try {
 *     val credentials = authClient.login("user@example.com", "password").await()
 * } catch (error: AuthenticationException) {
 *     if (error.isMultifactorRequired) {
 *         val mfaToken = error.mfaToken
 *         if (mfaToken != null) {
 *             val mfaClient = authClient.mfa(mfaToken)
 *             // Use mfaClient to handle MFA flow
 *         }
 *     }
 * }
 * ```
 */
public class MfaApiClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val mfaToken: String,
    private val factory: RequestFactory<AuthenticationException>,
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
        RequestFactory<AuthenticationException>(
            auth0.networkingClient,
            AuthenticationAPIClient.createErrorAdapter()
        ),
        GsonProvider.gson
    )

    private val clientId: String
        get() = auth0.clientId
    private val baseURL: String
        get() = auth0.getDomainUrl()

    /**
     * Get the list of available authenticators (MFA factors) enrolled for the user.
     *
     * Example usage:
     * ```
     * mfaClient.getAvailableAuthenticators()
     *     .start(object : Callback<List<Authenticator>, MfaListAuthenticatorsException> {
     *         override fun onSuccess(result: List<Authenticator>) { }
     *         override fun onFailure(error: MfaListAuthenticatorsException) { }
     *     })
     * ```
     *
     * Example with filtering:
     * ```
     * mfaClient.getAvailableAuthenticators(listOf("otp", "oob"))
     *     .start(object : Callback<List<Authenticator>, MfaListAuthenticatorsException> {
     *         override fun onSuccess(result: List<Authenticator>) {
     *             // Only OTP and OOB authenticators returned
     *         }
     *         override fun onFailure(error: MfaListAuthenticatorsException) { }
     *     })
     * ```
     *
     * @param factorsAllowed optional list of factor types to filter by (e.g., "otp", "oob", "recovery-code").
     *                       Pass null to retrieve all authenticators. Empty list is not allowed.
     * @return a request to configure and start that will yield a list of [Authenticator]
     * @throws MfaListAuthenticatorsException if factorsAllowed is an empty list (SDK validation error)
     */
    public fun getAvailableAuthenticators(
        factorsAllowed: List<String>? = null
    ): Request<List<Authenticator>, MfaListAuthenticatorsException> {
        // SDK validation: factorsAllowed cannot be empty
        if (factorsAllowed != null && factorsAllowed.isEmpty()) {
            throw MfaListAuthenticatorsException.invalidRequest(
                "challengeType is required and must contain at least one challenge type. " +
                "Pass null to retrieve all authenticators, or provide at least one factor type (e.g., \"otp\", \"oob\", \"recovery-code\")."
            )
        }
        
        val urlBuilder = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(MFA_PATH)
            .addPathSegment(AUTHENTICATORS_PATH)
        
        // Apply filtering if factorsAllowed is provided and not empty
        if (factorsAllowed != null) {
            urlBuilder.addQueryParameter("factorsAllowed", factorsAllowed.joinToString(","))
        }

        val url = urlBuilder.build()

        val authenticatorsAdapter: JsonAdapter<List<Authenticator>> = GsonAdapter.forListOf(
            Authenticator::class.java, gson
        )

        return listAuthenticatorsFactory.get(url.toString(), authenticatorsAdapter)
            .addHeader(HEADER_AUTHORIZATION, "Bearer $mfaToken")
    }

    /**
     * Send a challenge for an out-of-band (OOB) MFA authenticator (e.g., SMS, Push).
     * This will trigger the system to send the code to the user.
     *
     * Example usage:
     * ```
     * mfaClient.challenge("oob", "{authenticator_id}")
     *     .start(object : Callback<Challenge, MfaChallengeException> {
     *         override fun onSuccess(result: Challenge) {
             *             // Code sent, now prompt user for the OTP they received
     *         }
     *         override fun onFailure(error: MfaChallengeException) { }
     *     })
     * ```
     *
     * @param challengeType the type of challenge (e.g., "oob")
     * @param authenticatorId the ID of the authenticator to challenge
     * @return a request to configure and start that will yield [Challenge]
     */
    public fun challenge(
        challengeType: String,
        authenticatorId: String
    ): Request<Challenge, MfaChallengeException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(CHALLENGE_TYPE_KEY, challengeType)
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
     * Enroll a new MFA factor for the user. This is a generic enrollment method
     * that supports different factor types.
     *
     * Example usage for TOTP:
     * ```
     * mfaClient.enroll("totp")
     *     .start(object : Callback<EnrollmentChallenge, MfaEnrollmentException> {
     *         override fun onSuccess(result: EnrollmentChallenge) {
     *             if (result is TotpEnrollmentChallenge) {
     *                 // Show QR code to user: result.barcodeUri
     *             }
     *         }
     *         override fun onFailure(error: MfaEnrollmentException) { }
     *     })
     * ```
     *
     * @param factorType the type of factor to enroll (e.g., "totp", "phone", "email")
     * @param phoneNumber the phone number (required for SMS enrollment)
     * @param email the email address (required for email OTP enrollment)
     * @param authenticatorType optional authenticator type specification
     * @return a request to configure and start that will yield [EnrollmentChallenge]
     */
    public fun enroll(
        factorType: String,
        phoneNumber: String? = null,
        email: String? = null,
        authenticatorType: String? = null
    ): Request<EnrollmentChallenge, MfaEnrollmentException> {
        // Auth0 API expects authenticator_types as an array and oob_channels for OOB types
        // Map the factorType to the correct Auth0 API format
        val authenticatorTypesArray: List<String>
        val oobChannelsArray: List<String>?
        
        when (factorType.lowercase()) {
            "phone" -> {
                // SMS enrollment: authenticator_types=["oob"], oob_channels=["sms"]
                authenticatorTypesArray = listOf("oob")
                oobChannelsArray = listOf("sms")
            }
            "email" -> {
                // Email enrollment: authenticator_types=["oob"], oob_channels=["email"]
                authenticatorTypesArray = listOf("oob")
                oobChannelsArray = listOf("email")
            }
            "totp" -> {
                // TOTP enrollment: authenticator_types=["otp"]
                authenticatorTypesArray = listOf("otp")
                oobChannelsArray = null
            }
            "push" -> {
                // Push enrollment: authenticator_types=["push-notification"]
                authenticatorTypesArray = listOf("push-notification")
                oobChannelsArray = null
            }
            else -> {
                // Use authenticatorType if provided, otherwise use factorType as-is
                authenticatorTypesArray = if (authenticatorType != null) {
                    listOf(authenticatorType)
                } else {
                    listOf(factorType)
                }
                oobChannelsArray = null
            }
        }
        
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(PHONE_NUMBER_KEY, phoneNumber)
            .set(EMAIL_KEY, email)
            .asDictionary()

        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(MFA_PATH)
            .addPathSegment(ASSOCIATE_PATH)
            .build()

        val enrollmentAdapter: JsonAdapter<EnrollmentChallenge> = GsonAdapter(
            EnrollmentChallenge::class.java, gson
        )

        val request = enrollmentFactory.post(url.toString(), enrollmentAdapter)
            .addParameters(parameters)
        
        // Add array parameters using addParameter(name, Any) which handles serialization
        request.addParameter(AUTHENTICATOR_TYPES_KEY, authenticatorTypesArray)
        
        if (oobChannelsArray != null) {
            request.addParameter(OOB_CHANNELS_KEY, oobChannelsArray)
        }
        
        return request
    }

    /**
     * Convenience method to enroll a TOTP authenticator.
     *
     * Example usage:
     * ```
     * mfaClient.enrollTotp()
     *     .start(object : Callback<EnrollmentChallenge, MfaEnrollmentException> {
     *         override fun onSuccess(result: EnrollmentChallenge) {
     *             if (result is TotpEnrollmentChallenge) {
     *                 showQrCode(result.barcodeUri)
     *             }
     *         }
     *         override fun onFailure(error: MfaEnrollmentException) { }
     *     })
     * ```
     *
     * @return a request to configure and start that will yield [EnrollmentChallenge]
     */
    public fun enrollTotp(): Request<EnrollmentChallenge, MfaEnrollmentException> {
        return enroll("totp")
    }

    /**
     * Verify the MFA challenge with a one-time password (OTP).
     * This completes the MFA flow and returns the credentials.
     *
     * Example usage:
     * ```
     * mfaClient.verifyWithOtp("{otp_code}")
     *     .validateClaims() //mandatory
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) {
     *             // MFA completed successfully
     *         }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param otp the one-time password provided by the user
     * @return an authentication request to configure and start that will yield [Credentials]
     */
    public fun verifyWithOtp(otp: String): AuthenticationRequest {
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setGrantType(GRANT_TYPE_MFA_OTP)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(ONE_TIME_PASSWORD_KEY, otp)
            .asDictionary()

        return loginWithToken(parameters)
    }

    /**
     * Verify the MFA challenge with an out-of-band (OOB) code.
     * This is used for SMS or Push notification based MFA.
     *
     * Example usage:
     * ```
     * mfaClient.verifyWithOob("{oob_code}", "{binding_code}")
     *     .validateClaims() //mandatory
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) {
     *             // MFA completed successfully
     *         }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param oobCode the out-of-band code from the challenge response
     * @param bindingCode the binding code (OTP) entered by the user
     * @return an authentication request to configure and start that will yield [Credentials]
     */
    public fun verifyWithOob(oobCode: String, bindingCode: String): AuthenticationRequest {
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setGrantType(GRANT_TYPE_MFA_OOB)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(OUT_OF_BAND_CODE_KEY, oobCode)
            .set(BINDING_CODE_KEY, bindingCode)
            .asDictionary()

        return loginWithToken(parameters)
    }

    /**
     * Verify the MFA challenge with a recovery code.
     * Recovery codes are backup codes that can be used when other MFA methods are unavailable.
     *
     * Example usage:
     * ```
     * mfaClient.verifyWithRecoveryCode("{recovery_code}")
     *     .validateClaims() //mandatory
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) {
     *             // MFA completed successfully
     *             // result.recoveryCode contains a NEW recovery code to replace the used one
     *         }
     *         override fun onFailure(error: AuthenticationException) { }
     *     })
     * ```
     *
     * @param recoveryCode the recovery code to verify
     * @return an authentication request to configure and start that will yield [Credentials]
     */
    public fun verifyWithRecoveryCode(recoveryCode: String): AuthenticationRequest {
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setGrantType(GRANT_TYPE_MFA_RECOVERY_CODE)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(RECOVERY_CODE_KEY, recoveryCode)
            .asDictionary()

        return loginWithToken(parameters)
    }

    /**
     * Helper function to make a request to the /oauth/token endpoint.
     */
    private fun loginWithToken(parameters: Map<String, String>): AuthenticationRequest {
        val url = baseURL.toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()

        val requestParameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .addAll(parameters)
            .asDictionary()

        val credentialsAdapter: JsonAdapter<Credentials> = GsonAdapter(
            Credentials::class.java, gson
        )

        val request = BaseAuthenticationRequest(
            factory.post(url.toString(), credentialsAdapter), clientId, baseURL
        )
        request.addParameters(requestParameters)
        return request
    }

    /**
     * Creates error adapter for getAuthenticators() operations.
     * Returns MfaListAuthenticatorsException with fallback error code if API doesn't provide one.
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
                        code = MfaListAuthenticatorsException.FALLBACK_ERROR_CODE,
                        description = cause.message ?: "Something went wrong"
                    )
                }
            }
        }
    }

    /**
     * Creates error adapter for enroll() operations.
     * Returns MfaEnrollmentException with fallback error code if API doesn't provide one.
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
                        code = MfaEnrollmentException.FALLBACK_ERROR_CODE,
                        description = cause.message ?: "Something went wrong"
                    )
                }
            }
        }
    }

    /**
     * Creates error adapter for challenge() operations.
     * Returns MfaChallengeException with fallback error code if API doesn't provide one.
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
                        code = MfaChallengeException.FALLBACK_ERROR_CODE,
                        description = cause.message ?: "Something went wrong"
                    )
                }
            }
        }
    }

    /**
     * Creates error adapter for verify() operations.
     * Returns MfaVerifyException with fallback error code if API doesn't provide one.
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
                        code = MfaVerifyException.FALLBACK_ERROR_CODE,
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
