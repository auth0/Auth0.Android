package com.auth0.android.authentication

import com.auth0.android.Auth0Exception

/**
 * Base class for MFA-related exceptions.
 * All MFA-specific errors inherit from this class for easier error handling.
 */
public sealed class MfaException(
    message: String = "An error occurred during MFA operation",
    cause: Throwable? = null
) : Auth0Exception(message, cause) {

    /**
     * The error code from the API response or SDK validation
     */
    public abstract fun getCode(): String

    /**
     * The error description providing details about what went wrong
     */
    public abstract fun getDescription(): String

    /**
     * Http Response status code. Can have value of 0 if not set.
     */
    public abstract val statusCode: Int

    /**
     * Returns a value from the error map, if any.
     *
     * @param key key of the value to return
     * @return the value if found or null
     */
    public abstract fun getValue(key: String): Any?

    /**
     * Exception thrown when listing authenticators fails.
     *
     * SDK-thrown errors:
     * - `invalid_request`: challengeType is required and must contain at least one challenge type
     *
     * Additional errors may be returned by the Auth0 API and forwarded by the SDK.
     *
     * Example usage:
     * ```
     * try {
     *     val authenticators = mfaClient.getAvailableAuthenticators(listOf("otp", "oob")).await()
     * } catch (error: MfaListAuthenticatorsException) {
     *     when (error.getCode()) {
     *         "invalid_request" -> println("Invalid request: ${error.getDescription()}")
     *         else -> println("API error: ${error.getCode()} - ${error.getDescription()}")
     *     }
     * }
     * ```
     */
    public class MfaListAuthenticatorsException internal constructor(
        private val code: String,
        private val description: String,
        private val values: Map<String, Any> = emptyMap(),
        override val statusCode: Int = 0
    ) : MfaException("MFA authenticator listing failed: $code") {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: FALLBACK_ERROR_CODE,
            description = (values["error_description"] as? String) ?: "Failed to list authenticators",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]

        public companion object {
            internal const val FALLBACK_ERROR_CODE = "mfa_list_authenticators_error"
            internal const val INVALID_REQUEST = "invalid_request"
            
            /**
             * Creates an exception for SDK validation errors.
             */
            internal fun invalidRequest(description: String): MfaListAuthenticatorsException {
                return MfaListAuthenticatorsException(
                    code = INVALID_REQUEST,
                    description = description
                )
            }
        }
    }

    /**
     * Exception thrown when MFA enrollment fails.
     *
     * All errors come from the Auth0 API. If no error code is provided,
     * defaults to `mfa_enrollment_error`.
     *
     * Example usage:
     * ```
     * try {
     *     val challenge = mfaClient.enroll("phone", "+12025551234").await()
     * } catch (error: MfaEnrollmentException) {
     *     println("Enrollment failed: ${error.getCode()} - ${error.getDescription()}")
     * }
     * ```
     */
    public class MfaEnrollmentException internal constructor(
        private val code: String,
        private val description: String,
        private val values: Map<String, Any> = emptyMap(),
        override val statusCode: Int = 0
    ) : MfaException("MFA enrollment failed: $code") {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: FALLBACK_ERROR_CODE,
            description = (values["error_description"] as? String) ?: "Failed to enroll MFA authenticator",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]

        public companion object {
            internal const val FALLBACK_ERROR_CODE = "mfa_enrollment_error"
        }
    }

    /**
     * Exception thrown when MFA challenge fails.
     *
     * All errors come from the Auth0 API. If no error code is provided,
     * defaults to `mfa_challenge_error`.
     *
     * Example usage:
     * ```
     * try {
     *     val challenge = mfaClient.challenge("sms|dev_123").await()
     * } catch (error: MfaChallengeException) {
     *     println("Challenge failed: ${error.getCode()} - ${error.getDescription()}")
     * }
     * ```
     */
    public class MfaChallengeException internal constructor(
        private val code: String,
        private val description: String,
        private val values: Map<String, Any> = emptyMap(),
        override val statusCode: Int = 0
    ) : MfaException("MFA challenge failed: $code") {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: FALLBACK_ERROR_CODE,
            description = (values["error_description"] as? String) ?: "Failed to initiate MFA challenge",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]

        public companion object {
            internal const val FALLBACK_ERROR_CODE = "mfa_challenge_error"
        }
    }

    /**
     * Exception thrown when MFA verification fails.
     *
     * All errors come from the Auth0 API. If no error code is provided,
     * defaults to `mfa_verify_error`.
     *
     * Example usage:
     * ```
     * try {
     *     val credentials = mfaClient.verifyOtp("123456").await()
     * } catch (error: MfaVerifyException) {
     *     println("Verification failed: ${error.getCode()} - ${error.getDescription()}")
     * }
     * ```
     */
    public class MfaVerifyException internal constructor(
        private val code: String,
        private val description: String,
        private val values: Map<String, Any> = emptyMap(),
        override val statusCode: Int = 0
    ) : MfaException("MFA verification failed: $code") {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: FALLBACK_ERROR_CODE,
            description = (values["error_description"] as? String) ?: "Failed to verify MFA code",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]

        public companion object {
            internal const val FALLBACK_ERROR_CODE = "mfa_verify_error"
        }
    }

    /**
     * Exception thrown when MFA is required during token operations.
     *
     * This error is thrown when multi-factor authentication is required to complete
     * a login or token refresh operation. Use the [mfaToken] to create an [MfaApiClient]
     * and continue the MFA flow.
     *
     * Example usage:
     * ```
     * try {
     *     val credentials = authClient.login("user@example.com", "password").await()
     * } catch (error: MfaRequiredException) {
     *     val mfaToken = error.mfaToken
     *     val requirements = error.mfaRequirements
     *     
     *     // Check if user needs to enroll
     *     if (requirements?.enroll != null) {
     *         println("Available enrollment types: ${requirements.enroll}")
     *     }
     *     
     *     // Check if user can challenge existing factors
     *     if (requirements?.challenge != null) {
     *         println("Available challenge types: ${requirements.challenge}")
     *     }
     *     
     *     // Create MFA client to continue
     *     if (mfaToken != null) {
     *         val mfaClient = authClient.mfa(mfaToken)
     *         // Continue with MFA flow
     *     }
     * }
     * ```
     */
    public class MfaRequiredException internal constructor(
        private val values: Map<String, Any>,
        override val statusCode: Int = 0
    ) : MfaException("Multi-factor authentication required") {
        
        override fun getCode(): String = "mfa_required"
        override fun getDescription(): String = 
            (values["error_description"] as? String) ?: "Multi-factor authentication required"
        override fun getValue(key: String): Any? = values[key]

        /**
         * The MFA token to use for subsequent MFA operations
         */
        public val mfaToken: String?
            get() = getValue("mfa_token") as? String

        /**
         * The MFA requirements returned when multi-factor authentication is required.
         * Contains information about available enrollment and challenge types.
         */
        public val mfaRequirements: Map<String, Any>?
            get() = getValue("mfa_requirements") as? Map<String, Any>
    }
}
