package com.auth0.android.authentication.mfa

import com.auth0.android.Auth0Exception
import com.auth0.android.Auth0Exception.Companion.UNKNOWN_ERROR

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
     * - `invalid_request`: factorsAllowed is required and must contain at least one factor type
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
        override val statusCode: Int = 0,
        cause: Throwable? = null
    ) : MfaException("MFA authenticator listing failed: $code", cause) {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: UNKNOWN_ERROR,
            description = (values["error_description"] as? String) ?: "Failed to list authenticators",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]

        public companion object {
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
     * defaults to `a0.sdk.internal_error.unknown`.
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
        override val statusCode: Int = 0,
        cause: Throwable? = null
    ) : MfaException("MFA enrollment failed: $code", cause) {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: UNKNOWN_ERROR,
            description = (values["error_description"] as? String) ?: "Failed to enroll MFA authenticator",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]
    }

    /**
     * Exception thrown when MFA challenge fails.
     *
     * All errors come from the Auth0 API. If no error code is provided,
     * defaults to `a0.sdk.internal_error.unknown`.
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
        override val statusCode: Int = 0,
        cause: Throwable? = null
    ) : MfaException("MFA challenge failed: $code", cause) {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: UNKNOWN_ERROR,
            description = (values["error_description"] as? String) ?: "Failed to initiate MFA challenge",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]
    }

    /**
     * Exception thrown when MFA verification fails.
     *
     * All errors come from the Auth0 API. If no error code is provided,
     * defaults to `a0.sdk.internal_error.unknown`.
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
        override val statusCode: Int = 0,
        cause: Throwable? = null
    ) : MfaException("MFA verification failed: $code", cause) {

        internal constructor(values: Map<String, Any>, statusCode: Int) : this(
            code = (values["error"] as? String) ?: UNKNOWN_ERROR,
            description = (values["error_description"] as? String) ?: "Failed to verify MFA code",
            values = values,
            statusCode = statusCode
        )

        override fun getCode(): String = code
        override fun getDescription(): String = description
        override fun getValue(key: String): Any? = values[key]
    }
}
