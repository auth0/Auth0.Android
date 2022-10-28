package com.auth0.android.authentication

import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.request.internal.GsonProvider
import com.google.gson.reflect.TypeToken
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.FileReader
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.*

@RunWith(RobolectricTestRunner::class)
public class AuthenticationExceptionTest {
    @get:Rule
    public val exception: ExpectedException = ExpectedException.none()
    private lateinit var values: MutableMap<String, Any>

    @Before
    public fun setUp() {
        values = HashMap()
    }

    @Test
    public fun shouldGetUnknownCode() {
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getCode(),
            CoreMatchers.`is`(CoreMatchers.equalTo(Auth0Exception.UNKNOWN_ERROR))
        )
    }

    @Test
    public fun shouldGetPreferErrorOverCode() {
        values[ERROR_KEY] = "a_valid_error"
        values[CODE_KEY] = "a_valid_code"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getCode(),
            CoreMatchers.`is`(CoreMatchers.equalTo("a_valid_error"))
        )
    }

    @Test
    public fun shouldGetValidCode() {
        values[CODE_KEY] = "a_valid_code"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getCode(),
            CoreMatchers.`is`(CoreMatchers.equalTo("a_valid_code"))
        )
    }

    @Test
    public fun shouldGetValidError() {
        values[ERROR_KEY] = "a_valid_error"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getCode(),
            CoreMatchers.`is`(CoreMatchers.equalTo("a_valid_error"))
        )
    }

    @Test
    public fun shouldGetPreferDescriptionOverErrorDescription() {
        values[ERROR_DESCRIPTION_KEY] = "a_valid_error_description"
        values[DESCRIPTION_KEY] = "a_valid_description"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getDescription(),
            CoreMatchers.`is`(CoreMatchers.equalTo("a_valid_description"))
        )
    }

    @Test
    public fun shouldGetValidDescription() {
        values[DESCRIPTION_KEY] = "a_valid_error_description"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getDescription(),
            CoreMatchers.`is`(CoreMatchers.equalTo("a_valid_error_description"))
        )
    }

    @Test
    public fun shouldGetValidErrorDescription() {
        values[ERROR_DESCRIPTION_KEY] = "a_valid_error_description"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getDescription(),
            CoreMatchers.`is`(CoreMatchers.equalTo("a_valid_error_description"))
        )
    }

    @Test
    public fun shouldGetPlainTextAsDescription() {
        val ex = AuthenticationException("Payload", 404)
        MatcherAssert.assertThat(
            ex.getDescription(),
            CoreMatchers.`is`(CoreMatchers.equalTo("Payload"))
        )
    }

    @Test
    public fun shouldGetMessageWithUnknownCodeIfNullDescription() {
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getDescription(),
            CoreMatchers.`is`(
                CoreMatchers.equalTo(
                    String.format(
                        "Received error with code %s",
                        Auth0Exception.UNKNOWN_ERROR
                    )
                )
            )
        )
    }

    @Test
    public fun shouldNotGetEmptyDescription() {
        values[CODE_KEY] = "a_valid_code"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(
            ex.getDescription(),
            CoreMatchers.`is`(CoreMatchers.equalTo("Failed with unknown error"))
        )
    }

    @Test
    public fun shouldGetValuesFromTheMap() {
        values["key"] = "value"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.getValue("key"), CoreMatchers.`is`(CoreMatchers.notNullValue()))
        MatcherAssert.assertThat(
            ex.getValue("key"), CoreMatchers.`is`(
                CoreMatchers.instanceOf(
                    String::class.java
                )
            )
        )
        MatcherAssert.assertThat(
            ex.getValue("key") as String?,
            CoreMatchers.`is`(CoreMatchers.equalTo("value"))
        )
    }

    @Test
    public fun shouldReturnNullIfMapDoesNotExist() {
        val ex1 = AuthenticationException("code", "description")
        val ex2 = AuthenticationException("message")
        val ex3 = AuthenticationException("code", Auth0Exception("message"))
        val ex4 = AuthenticationException("credentials", 1)
        MatcherAssert.assertThat(ex1.getValue("key"), CoreMatchers.`is`(CoreMatchers.nullValue()))
        MatcherAssert.assertThat(ex2.getValue("key"), CoreMatchers.`is`(CoreMatchers.nullValue()))
        MatcherAssert.assertThat(ex3.getValue("key"), CoreMatchers.`is`(CoreMatchers.nullValue()))
        MatcherAssert.assertThat(ex4.getValue("key"), CoreMatchers.`is`(CoreMatchers.nullValue()))
    }

    @Test
    public fun shouldNotHaveNetworkError() {
        val ex = AuthenticationException("Something else happened")
        MatcherAssert.assertThat(ex.isNetworkError, CoreMatchers.`is`(false))
    }

    @Test
    public fun shouldHaveNetworkError() {
        val ex = AuthenticationException(
            "Request has definitely failed", NetworkErrorException(
                IOException()
            )
        )
        MatcherAssert.assertThat(ex.isNetworkError, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveNetworkErrorForSocketTimeout() {
        val ex = AuthenticationException(
            "Request has definitely failed", Auth0Exception("",
                SocketTimeoutException()
            )
        )
        MatcherAssert.assertThat(ex.isNetworkError, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveNetworkErrorForUnknownHost() {
        val ex = AuthenticationException(
            "Request has definitely failed", NetworkErrorException(
                UnknownHostException()
            )
        )
        MatcherAssert.assertThat(ex.isNetworkError, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveRequestVerificationError() {
        values[CODE_KEY] = "requires_verification"
        values[ERROR_DESCRIPTION_KEY] = "Suspicious request requires verification"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isVerificationRequired, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveExpiredMultifactorTokenOnOIDCMode() {
        values[ERROR_KEY] = "expired_token"
        values[ERROR_DESCRIPTION_KEY] = "mfa_token is expired"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorTokenInvalid, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveMalformedMultifactorTokenOnOIDCMode() {
        values[ERROR_KEY] = "invalid_grant"
        values[ERROR_DESCRIPTION_KEY] = "Malformed mfa_token"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorTokenInvalid, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldRequireMultifactorOnOIDCMode() {
        values[ERROR_KEY] = "mfa_required"
        values["mfa_token"] = "some-random-token"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorRequired, CoreMatchers.`is`(true))
        MatcherAssert.assertThat(
            ex.getValue("mfa_token") as String?,
            CoreMatchers.`is`("some-random-token")
        )
    }

    @Test
    public fun shouldRequireMultifactor() {
        values[CODE_KEY] = "a0.mfa_required"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorRequired, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldRequireMultifactorEnrollOnOIDCMode() {
        values[ERROR_KEY] = "unsupported_challenge_type"
        values[ERROR_DESCRIPTION_KEY] = "User is not enrolled with guardian"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorEnrollRequired, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldRequireMultifactorEnroll() {
        values[CODE_KEY] = "a0.mfa_registration_required"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorEnrollRequired, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveInvalidMultifactorCodeOnOIDCMode() {
        values[ERROR_KEY] = "invalid_grant"
        values[ERROR_DESCRIPTION_KEY] = "Invalid otp_code."
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorCodeInvalid, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveInvalidMultifactorCode() {
        values[CODE_KEY] = "a0.mfa_invalid_code"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isMultifactorCodeInvalid, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveNotStrongPassword() {
        values[CODE_KEY] = "invalid_password"
        values[NAME_KEY] = "PasswordStrengthError"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isPasswordNotStrongEnough, CoreMatchers.`is`(true))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldHaveNotStrongPasswordWithDetailedDescription() {
        val fr = FileReader(PASSWORD_STRENGTH_ERROR_RESPONSE)
        val mapType = object : TypeToken<Map<String, Any>>() {}
        val mapPayload: Map<String, Any> = GsonProvider.gson.getAdapter(mapType).fromJson(fr)
        val ex = AuthenticationException(mapPayload)
        MatcherAssert.assertThat(ex.isPasswordNotStrongEnough, CoreMatchers.`is`(true))
        val expectedDescription =
            "At least 10 characters in length; Contain at least 3 of the following 4 types of characters: lower case letters (a-z), upper case letters (A-Z), numbers (i.e. 0-9), special characters (e.g. !@#$%^&*); Should contain: lower case letters (a-z), upper case letters (A-Z), numbers (i.e. 0-9), special characters (e.g. !@#$%^&*); No more than 2 identical characters in a row (e.g., \"aaa\" not allowed)"
        MatcherAssert.assertThat(ex.getDescription(), CoreMatchers.`is`(expectedDescription))
    }

    @Test
    public fun shouldHaveAlreadyUsedPassword() {
        values[CODE_KEY] = "invalid_password"
        values[NAME_KEY] = "PasswordHistoryError"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isPasswordAlreadyUsed, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveRuleError() {
        values[CODE_KEY] = "unauthorized"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isRuleError, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveInvalidCredentials() {
        values[CODE_KEY] = "invalid_user_password"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isInvalidCredentials, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveOIDCInvalidCredentials() {
        values[CODE_KEY] = "invalid_grant"
        values[ERROR_DESCRIPTION_KEY] = "Wrong email or password."
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isInvalidCredentials, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveInvalidCredentialsOnPhonePasswordless() {
        values[ERROR_KEY] = "invalid_grant"
        values[ERROR_DESCRIPTION_KEY] = "Wrong phone number or verification code."
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isInvalidCredentials, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveInvalidCredentialsOnEmailPasswordless() {
        values[ERROR_KEY] = "invalid_grant"
        values[ERROR_DESCRIPTION_KEY] = "Wrong email or verification code."
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isInvalidCredentials, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveAccessDenied() {
        values[CODE_KEY] = "access_denied"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isAccessDenied, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveInvalidAuthorizeUrl() {
        values[CODE_KEY] = "a0.invalid_authorize_url"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isInvalidAuthorizeURL, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveInvalidConfiguration() {
        values[CODE_KEY] = "a0.invalid_configuration"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isInvalidConfiguration, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveAuthenticationCanceled() {
        values[CODE_KEY] = "a0.authentication_canceled"
        val ex = AuthenticationException(
            values
        )
        @Suppress("DEPRECATION")
        MatcherAssert.assertThat(ex.isAuthenticationCanceled, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveCanceled() {
        values[CODE_KEY] = "a0.authentication_canceled"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isCanceled, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHavePasswordLeaked() {
        values[CODE_KEY] = "password_leaked"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isPasswordLeaked, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveLoginRequired() {
        values[CODE_KEY] = "login_required"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isLoginRequired, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveMissingBrowserApp() {
        values[CODE_KEY] = "a0.browser_not_available"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isBrowserAppNotAvailable, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHavePKCENotAvailable() {
        values[CODE_KEY] = "a0.pkce_not_available"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isPKCENotAvailable, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveRefreshTokenDeleted() {
        values[ERROR_KEY] = "invalid_grant"
        values[ERROR_DESCRIPTION_KEY] =
            "The refresh_token was generated for a user who doesn't exist anymore."
        val ex = AuthenticationException(values, 403)
        MatcherAssert.assertThat(ex.isRefreshTokenDeleted, CoreMatchers.`is`(true))
    }

    @Test
    public fun shouldHaveTooManyAttempts() {
        values[CODE_KEY] = "too_many_attempts"
        val ex = AuthenticationException(
            values
        )
        MatcherAssert.assertThat(ex.isTooManyAttempts, CoreMatchers.`is`(true))
    }

    private companion object {
        private const val PASSWORD_STRENGTH_ERROR_RESPONSE =
            "src/test/resources/password_strength_error.json"
        private const val CODE_KEY = "code"
        private const val NAME_KEY = "name"
        private const val ERROR_KEY = "error"
        private const val ERROR_DESCRIPTION_KEY = "error_description"
        private const val DESCRIPTION_KEY = "description"
    }
}
