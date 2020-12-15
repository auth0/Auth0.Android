/*
 * AuthenticationException.java
 *
 * Copyright (c) 2016 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.auth0.android.authentication;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Log;

import com.auth0.android.Auth0Exception;
import com.auth0.android.NetworkErrorException;

import java.util.HashMap;
import java.util.Map;

public class AuthenticationException extends Auth0Exception {

    private static final String ERROR_KEY = "error";
    private static final String CODE_KEY = "code";
    private static final String DESCRIPTION_KEY = "description";
    private static final String ERROR_DESCRIPTION_KEY = "error_description";
    private static final String NAME_KEY = "name";

    private static final String DEFAULT_MESSAGE = "An error occurred when trying to authenticate with the server.";

    private static final String ERROR_OIDC_ACCESS_TOKEN = "OIDC conformant clients cannot use /oauth/access_token";
    private static final String ERROR_OIDC_RO = "OIDC conformant clients cannot use /oauth/ro";

    private String code;
    private String description;
    private int statusCode;
    private Map<String, Object> values;

    public AuthenticationException(@NonNull String code, @NonNull String description) {
        this(DEFAULT_MESSAGE);
        this.code = code;
        this.description = description;
    }

    public AuthenticationException(@NonNull String message) {
        super(message);
    }

    public AuthenticationException(@NonNull String message, @Nullable Auth0Exception exception) {
        super(message, exception);
    }

    public AuthenticationException(@Nullable String payload, int statusCode) {
        this(DEFAULT_MESSAGE);
        this.code = payload != null ? NON_JSON_ERROR : EMPTY_BODY_ERROR;
        this.description = payload != null ? payload : EMPTY_RESPONSE_BODY_DESCRIPTION;
        this.statusCode = statusCode;
    }

    public AuthenticationException(@NonNull Map<String, Object> values) {
        this(DEFAULT_MESSAGE);
        this.values = new HashMap<>(values);

        String codeValue = (String) (this.values.containsKey(ERROR_KEY) ? this.values.get(ERROR_KEY) : this.values.get(CODE_KEY));
        this.code = codeValue != null ? codeValue : UNKNOWN_ERROR;
        if (!this.values.containsKey(DESCRIPTION_KEY)) {
            this.description = (String) this.values.get(ERROR_DESCRIPTION_KEY);
            warnIfOIDCError();
            return;
        }

        Object description = this.values.get(DESCRIPTION_KEY);
        if (description instanceof String) {
            this.description = (String) description;
        } else if (description instanceof Map && isPasswordNotStrongEnough()) {
            @SuppressWarnings("unchecked")
            PasswordStrengthErrorParser pwStrengthParser = new PasswordStrengthErrorParser((Map<String, Object>) description);
            this.description = pwStrengthParser.getDescription();
        }
    }

    private void warnIfOIDCError() {
        if ("invalid_request".equals(getCode()) && (ERROR_OIDC_ACCESS_TOKEN.equals(getDescription()) || ERROR_OIDC_RO.equals(getDescription()))) {
            Log.w(AuthenticationAPIClient.class.getSimpleName(), "Your Auth0 Application is configured as 'OIDC Conformant' but this instance it's not. To authenticate you will need to enable the flag by calling Auth0#setOIDCConformant(true) on the Auth0 instance you used in the setup.");
        }
    }

    /**
     * Auth0 error code if the server returned one or an internal library code (e.g.: when the server could not be reached)
     *
     * @return the error code.
     */
    @NonNull
    public String getCode() {
        return code != null ? code : UNKNOWN_ERROR;
    }

    /**
     * Http Response status code. Can have value of 0 if not set.
     *
     * @return the status code.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Description of the error.
     * important: You should avoid displaying description to the user, it's meant for debugging only.
     *
     * @return the error description.
     */
    @NonNull
    public String getDescription() {
        if (!TextUtils.isEmpty(description)) {
            return description;
        }
        if (UNKNOWN_ERROR.equals(getCode())) {
            return String.format("Received error with code %s", getCode());
        }
        return "Failed with unknown error";
    }

    /**
     * Returns a value from the error map, if any.
     *
     * @param key key of the value to return
     * @return the value if found or null
     */
    @Nullable
    public Object getValue(@NonNull String key) {
        if (values == null) {
            return null;
        }
        return values.get(key);
    }

    // When the request failed due to network issues
    public boolean isNetworkError() {
        return getCause() instanceof NetworkErrorException;
    }

    // When there is no Browser app installed to handle the web authentication
    public boolean isBrowserAppNotAvailable() {
        return "a0.browser_not_available".equals(code);
    }

    // When the Authorize URL is invalid
    public boolean isInvalidAuthorizeURL() {
        return "a0.invalid_authorize_url".equals(code);
    }

    // When a Social Provider Configuration is invalid
    public boolean isInvalidConfiguration() {
        return "a0.invalid_configuration".equals(code);
    }

    // When a user closes the browser app and in turn, cancels the authentication
    public boolean isAuthenticationCanceled() {
        return "a0.authentication_canceled".equals(code);
    }

    /// When MFA code is required to authenticate
    public boolean isMultifactorRequired() {
        return "mfa_required".equals(code) || "a0.mfa_required".equals(code);
    }

    /// When MFA is required and the user is not enrolled
    public boolean isMultifactorEnrollRequired() {
        return "a0.mfa_registration_required".equals(code) || "unsupported_challenge_type".equals(code);
    }

    /// When Bot Protection flags the request as suspicious
    public boolean isVerificationRequired() {
        return "requires_verification".equals(code);
    }

    /// When the MFA Token used on the login request is malformed or has expired
    public boolean isMultifactorTokenInvalid() {
        return "expired_token".equals(code) && "mfa_token is expired".equals(description) ||
                "invalid_grant".equals(code) && "Malformed mfa_token".equals(description);
    }

    /// When MFA code sent is invalid or expired
    public boolean isMultifactorCodeInvalid() {
        return "a0.mfa_invalid_code".equals(code) 
            || "invalid_grant".equals(code) && "Invalid otp_code.".equals(description);
    }

    /// When password used for SignUp does not match connection's strength requirements.
    public boolean isPasswordNotStrongEnough() {
        return "invalid_password".equals(code) && "PasswordStrengthError".equals(values.get(NAME_KEY));
    }

    /// When password used for SignUp was already used before (Reported when password history feature is enabled).
    public boolean isPasswordAlreadyUsed() {
        return "invalid_password".equals(code) && "PasswordHistoryError".equals(values.get(NAME_KEY));
    }

    // When password used was reported to be leaked and a different one is required
    public boolean isPasswordLeaked() {
        return "password_leaked".equals(code);
    }

    /// When Auth0 rule returns an error. The message returned by the rule will be in `description`
    public boolean isRuleError() {
        return "unauthorized".equals(code);
    }

    /// When username and/or password used for authentication are invalid
    public boolean isInvalidCredentials() {
        return "invalid_user_password".equals(code)
                || "invalid_grant".equals(code) && "Wrong email or password.".equals(description)
                || "invalid_grant".equals(code) && "Wrong phone number or verification code.".equals(description)
                || "invalid_grant".equals(code) && "Wrong email or verification code.".equals(description);
    }

    /// When authenticating with web-based authentication and the resource server denied access per OAuth2 spec
    public boolean isAccessDenied() {
        return "access_denied".equals(code);
    }

    /// When authenticating with web-based authentication using prompt=none and the auth0 session had expired
    public boolean isLoginRequired() {
        return "login_required".equals(code);
    }

}
