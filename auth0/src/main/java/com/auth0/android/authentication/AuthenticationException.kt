package com.auth0.android.authentication

import android.text.TextUtils
import android.util.Log
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.provider.TokenValidationException
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.result.MfaRequirements

public class AuthenticationException : Auth0Exception {
    private var code: String? = null
    private var description: String? = null

    /**
     * Http Response status code. Can have value of 0 if not set.
     *
     * @return the status code.
     */
    public var statusCode: Int = 0
        private set
    private var values: Map<String, Any>? = null

    public constructor(code: String, description: String) : this(DEFAULT_MESSAGE) {
        this.code = code
        this.description = description
    }

    public constructor(message: String, cause: Exception? = null) : super(message, cause)

    public constructor(code: String, description: String, cause: Exception) : this(
        DEFAULT_MESSAGE,
        cause
    ) {
        this.code = code
        this.description = description
    }

    public constructor(payload: String?, statusCode: Int) : this(DEFAULT_MESSAGE) {
        code = if (payload != null) NON_JSON_ERROR else EMPTY_BODY_ERROR
        description = payload ?: EMPTY_RESPONSE_BODY_DESCRIPTION
        this.statusCode = statusCode
    }

    @JvmOverloads
    public constructor(values: Map<String, Any>, statusCode: Int = 0) : this(DEFAULT_MESSAGE) {
        this.statusCode = statusCode
        this.values = values
        val codeValue: String? =
            (if (values.containsKey(ERROR_KEY)) values[ERROR_KEY] else values[CODE_KEY]) as String?
        code = codeValue ?: UNKNOWN_ERROR
        if (!values.containsKey(DESCRIPTION_KEY)) {
            description = values[ERROR_DESCRIPTION_KEY] as String?
            warnIfOIDCError()
            return
        }
        val description = values[DESCRIPTION_KEY]
        if (description is String) {
            this.description = description
        } else if (description is Map<*, *> && isPasswordNotStrongEnough) {
            val pwStrengthParser = PasswordStrengthErrorParser(description as Map<String, Any>)
            this.description = pwStrengthParser.description
        }
    }

    private fun warnIfOIDCError() {
        if ("invalid_request" == getCode() && (ERROR_OIDC_ACCESS_TOKEN == getDescription() || ERROR_OIDC_RO == getDescription())) {
            Log.w(
                AuthenticationAPIClient::class.java.simpleName,
                "Your Auth0 Application is configured as 'OIDC Conformant' but this instance it's not. To authenticate you will need to enable the flag by calling Auth0#setOIDCConformant(true) on the Auth0 instance you used in the setup."
            )
        }
    }

    /**
     * Auth0 error code if the server returned one or an internal library code (e.g.: when the server could not be reached)
     *
     * @return the error code.
     */
    public fun getCode(): String {
        return if (code != null) code!! else UNKNOWN_ERROR
    }

    /**
     * Description of the error.
     * important: You should avoid displaying description to the user, it's meant for debugging only.
     *
     * @return the error description.
     */
    public fun getDescription(): String {
        if (!TextUtils.isEmpty(description)) {
            return description!!
        }
        return if (UNKNOWN_ERROR != getCode()) {
            String.format("Received error with code %s", getCode())
        } else "Failed with unknown error"
    }

    /**
     * Returns a value from the error map, if any.
     *
     * @param key key of the value to return
     * @return the value if found or null
     */
    public fun getValue(key: String): Any? {
        return if (values == null) {
            null
        } else values!![key]
    }

    // When the request failed due to network issues
    public val isNetworkError: Boolean
        get() = cause is NetworkErrorException

    // When there is no Browser app installed to handle the web authentication
    public val isBrowserAppNotAvailable: Boolean
        get() = "a0.browser_not_available" == code

    /**
     * When the required algorithms to support PKCE web authentication is    not available on the device
     */
    public val isPKCENotAvailable: Boolean
        get() = "a0.pkce_not_available" == code

    // When the Authorize URL is invalid
    public val isInvalidAuthorizeURL: Boolean
        get() = "a0.invalid_authorize_url" == code

    // When a Social Provider Configuration is invalid
    public val isInvalidConfiguration: Boolean
        get() = "a0.invalid_configuration" == code

    // When a user closes the browser app and in turn, cancels the authentication
    @Deprecated(
        "This property can refer to both log in and log out actions.",
        replaceWith = ReplaceWith("isCanceled")
    )
    public val isAuthenticationCanceled: Boolean
        get() = isCanceled

    public val isCanceled: Boolean
        get() = "a0.authentication_canceled" == code

    /// When MFA code is required to authenticate
    public val isMultifactorRequired: Boolean
        get() = "mfa_required" == code || "a0.mfa_required" == code

    /// When MFA is required and the user is not enrolled
    public val isMultifactorEnrollRequired: Boolean
        get() = "a0.mfa_registration_required" == code || "unsupported_challenge_type" == code

    /**
     * The MFA token returned when multi-factor authentication is required.
     * This token should be used to create an [MfaApiClient] to continue the MFA flow.
     */
    public val mfaToken: String?
        get() = getValue("mfa_token") as? String

    /**
     * The MFA requirements returned when multi-factor authentication is required.
     * Contains information about the required challenge types.
     */
    public val mfaRequirements: MfaRequirements?
        get() = (getValue("mfa_requirements") as? Map<*, *>)?.let {
            @Suppress("UNCHECKED_CAST")
            GsonProvider.gson.fromJson(
                GsonProvider.gson.toJson(it),
                MfaRequirements::class.java
            )
        }

    /// When Bot Protection flags the request as suspicious
    public val isVerificationRequired: Boolean
        get() = "requires_verification" == code

    /// When the MFA Token used on the login request is malformed or has expired
    public val isMultifactorTokenInvalid: Boolean
        get() = "expired_token" == code && "mfa_token is expired" == description ||
                "invalid_grant" == code && "Malformed mfa_token" == description

    /// When MFA code sent is invalid or expired
    public val isMultifactorCodeInvalid: Boolean
        get() = "a0.mfa_invalid_code" == code || "invalid_grant" == code && "Invalid otp_code." == description
                || code == "invalid_grant" && description == "Invalid binding_code."
                || code == "invalid_grant" && description == "MFA Authorization rejected."

    /// When password used for SignUp does not match connection's strength requirements.
    public val isPasswordNotStrongEnough: Boolean
        get() = "invalid_password" == code && "PasswordStrengthError" == values!![NAME_KEY]

    /// When password used for SignUp was already used before (Reported when password history feature is enabled).
    public val isPasswordAlreadyUsed: Boolean
        get() = "invalid_password" == code && "PasswordHistoryError" == values!![NAME_KEY]

    // When password used was reported to be leaked and a different one is required
    public val isPasswordLeaked: Boolean
        get() = "password_leaked" == code

    /// When Auth0 rule returns an error. The message returned by the rule will be in `description`
    public val isRuleError: Boolean
        get() = "unauthorized" == code

    /// When username and/or password used for authentication are invalid
    public val isInvalidCredentials: Boolean
        get() = "invalid_user_password" == code || "invalid_grant" == code && "Wrong email or password." == description || "invalid_grant" == code && "Wrong phone number or verification code." == description || "invalid_grant" == code && "Wrong email or verification code." == description

    /// When authenticating with web-based authentication and the resource server denied access per OAuth2 spec
    public val isAccessDenied: Boolean
        get() = "access_denied" == code

    /// When authenticating with web-based authentication using prompt=none and the auth0 session had expired
    public val isLoginRequired: Boolean
        get() = "login_required" == code

    /// User is deleted
    public val isRefreshTokenDeleted: Boolean
        get() = "invalid_grant" == code
                && 403 == statusCode
                && "The refresh_token was generated for a user who doesn't exist anymore." == description

    // When the provided refresh token is invalid or expired
    public val isInvalidRefreshToken: Boolean
        get() = "invalid_grant" == code
                && "Unknown or invalid refresh token." == description

    // ID token validation error
    public val isIdTokenValidationError: Boolean
        get() = cause is TokenValidationException

    /// When the user is blocked due to too many attempts to log in
    public val isTooManyAttempts: Boolean
        get() = "too_many_attempts" == code

    internal companion object {
        internal const val ERROR_VALUE_AUTHENTICATION_CANCELED = "a0.authentication_canceled"
        internal const val ERROR_KEY_URI_NULL = "a0.auth.authorize_uri"
        internal const val ERROR_VALUE_AUTHORIZE_URI_INVALID =
            "Authorization URI is received as null from the intent"
        internal const val ERROR_KEY_CT_OPTIONS_NULL = "a0.auth.ct_options"
        internal const val ERROR_VALUE_CT_OPTIONS_INVALID =
            "Custom tab options are received as null from the intent"
        private const val ERROR_KEY = "error"
        private const val CODE_KEY = "code"
        private const val DESCRIPTION_KEY = "description"
        private const val ERROR_DESCRIPTION_KEY = "error_description"
        private const val NAME_KEY = "name"
        private const val DEFAULT_MESSAGE =
            "An error occurred when trying to authenticate with the server."
        private const val ERROR_OIDC_ACCESS_TOKEN =
            "OIDC conformant clients cannot use /oauth/access_token"
        private const val ERROR_OIDC_RO = "OIDC conformant clients cannot use /oauth/ro"
    }
}
