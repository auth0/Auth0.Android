package com.auth0.android.authentication

import com.auth0.android.authentication.MfaException.*
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Unit tests for MFA exception classes.
 */
@RunWith(RobolectricTestRunner::class)
public class MfaExceptionTest {


    @Test
    public fun shouldCreateMfaListAuthenticatorsExceptionFromValues(): Unit {
        val values = mapOf(
            "error" to "access_denied",
            "error_description" to "The MFA token is invalid"
        )
        val exception = MfaListAuthenticatorsException(values, 401)

        assertThat(exception.getCode(), `is`("access_denied"))
        assertThat(exception.getDescription(), `is`("The MFA token is invalid"))
        assertThat(exception.statusCode, `is`(401))
        assertThat(exception.message, containsString("access_denied"))
    }

    @Test
    public fun shouldMfaListAuthenticatorsExceptionGetCustomValue(): Unit {
        val values = mapOf(
            "error" to "custom_error",
            "error_description" to "Custom description",
            "custom_field" to "custom_value",
            "another_field" to 123.0
        )
        val exception = MfaListAuthenticatorsException(values, 400)

        assertThat(exception.getValue("custom_field"), `is`("custom_value"))
        assertThat(exception.getValue("another_field"), `is`(123.0))
        assertThat(exception.getValue("non_existent"), `is`(nullValue()))
    }

    @Test
    public fun shouldMfaListAuthenticatorsExceptionUseDefaultsWhenMissing(): Unit {
        val values = emptyMap<String, Any>()
        val exception = MfaListAuthenticatorsException(values, 500)

        assertThat(exception.getCode(), `is`("a0.sdk.internal_error.unknown"))
        assertThat(exception.getDescription(), `is`("Failed to list authenticators"))
    }

    @Test
    public fun shouldCreateInvalidRequestException(): Unit {
        val exception = MfaListAuthenticatorsException.invalidRequest(
            "factorsAllowed is required and must contain at least one challenge type."
        )

        assertThat(exception.getCode(), `is`("invalid_request"))
        assertThat(exception.getDescription(), containsString("factorsAllowed is required"))
        assertThat(exception.statusCode, `is`(0))
    }


    @Test
    public fun shouldCreateMfaEnrollmentExceptionFromValues(): Unit {
        val values = mapOf(
            "error" to "invalid_phone_number",
            "error_description" to "The phone number format is invalid"
        )
        val exception = MfaEnrollmentException(values, 400)

        assertThat(exception.getCode(), `is`("invalid_phone_number"))
        assertThat(exception.getDescription(), `is`("The phone number format is invalid"))
        assertThat(exception.statusCode, `is`(400))
        assertThat(exception.message, containsString("invalid_phone_number"))
    }

    @Test
    public fun shouldMfaEnrollmentExceptionGetCustomValue(): Unit {
        val values = mapOf(
            "error" to "enrollment_failed",
            "error_description" to "Enrollment failed",
            "authenticator_type" to "oob"
        )
        val exception = MfaEnrollmentException(values, 400)

        assertThat(exception.getValue("authenticator_type"), `is`("oob"))
        assertThat(exception.getValue("missing_key"), `is`(nullValue()))
    }

    @Test
    public fun shouldMfaEnrollmentExceptionUseDefaultsWhenMissing(): Unit {
        val values = emptyMap<String, Any>()
        val exception = MfaEnrollmentException(values, 500)

        assertThat(exception.getCode(), `is`("a0.sdk.internal_error.unknown"))
        assertThat(exception.getDescription(), `is`("Failed to enroll MFA authenticator"))
    }

    @Test
    public fun shouldMfaEnrollmentExceptionHandleNullValues(): Unit {
        val values = mapOf(
            "error" to "test_error",
            "null_value" to null
        )
        val exception = MfaEnrollmentException(values as Map<String, Any>, 400)

        assertThat(exception.getCode(), `is`("test_error"))
        assertThat(exception.getValue("null_value"), `is`(nullValue()))
    }


    @Test
    public fun shouldCreateMfaChallengeExceptionFromValues(): Unit {
        val values = mapOf(
            "error" to "invalid_authenticator",
            "error_description" to "The authenticator ID is not valid"
        )
        val exception = MfaChallengeException(values, 404)

        assertThat(exception.getCode(), `is`("invalid_authenticator"))
        assertThat(exception.getDescription(), `is`("The authenticator ID is not valid"))
        assertThat(exception.statusCode, `is`(404))
        assertThat(exception.message, containsString("invalid_authenticator"))
    }

    @Test
    public fun shouldMfaChallengeExceptionGetCustomValue(): Unit {
        val values = mapOf(
            "error" to "challenge_failed",
            "error_description" to "Challenge failed",
            "challenge_type" to "oob"
        )
        val exception = MfaChallengeException(values, 400)

        assertThat(exception.getValue("challenge_type"), `is`("oob"))
        assertThat(exception.getValue("missing_key"), `is`(nullValue()))
    }

    @Test
    public fun shouldMfaChallengeExceptionUseDefaultsWhenMissing(): Unit {
        val values = emptyMap<String, Any>()
        val exception = MfaChallengeException(values, 500)

        assertThat(exception.getCode(), `is`("a0.sdk.internal_error.unknown"))
        assertThat(exception.getDescription(), `is`("Failed to initiate MFA challenge"))
    }

    @Test
    public fun shouldMfaChallengeExceptionHandleMfaTokenExpired(): Unit {
        val values = mapOf(
            "error" to "expired_token",
            "error_description" to "The mfa_token has expired"
        )
        val exception = MfaChallengeException(values, 401)

        assertThat(exception.getCode(), `is`("expired_token"))
        assertThat(exception.getDescription(), `is`("The mfa_token has expired"))
        assertThat(exception.statusCode, `is`(401))
    }


    @Test
    public fun shouldCreateMfaVerifyExceptionFromValues(): Unit {
        val values = mapOf(
            "error" to "invalid_grant",
            "error_description" to "The OTP code is invalid"
        )
        val exception = MfaVerifyException(values, 403)

        assertThat(exception.getCode(), `is`("invalid_grant"))
        assertThat(exception.getDescription(), `is`("The OTP code is invalid"))
        assertThat(exception.statusCode, `is`(403))
        assertThat(exception.message, containsString("invalid_grant"))
    }

    @Test
    public fun shouldMfaVerifyExceptionGetCustomValue(): Unit {
        val values = mapOf(
            "error" to "invalid_code",
            "error_description" to "Invalid code",
            "attempts_remaining" to 2.0
        )
        val exception = MfaVerifyException(values, 400)

        assertThat(exception.getValue("attempts_remaining"), `is`(2.0))
        assertThat(exception.getValue("missing_key"), `is`(nullValue()))
    }

    @Test
    public fun shouldMfaVerifyExceptionUseDefaultsWhenMissing(): Unit {
        val values = emptyMap<String, Any>()
        val exception = MfaVerifyException(values, 500)

        assertThat(exception.getCode(), `is`("a0.sdk.internal_error.unknown"))
        assertThat(exception.getDescription(), `is`("Failed to verify MFA code"))
    }

    @Test
    public fun shouldMfaVerifyExceptionHandleMfaTokenExpired(): Unit {
        val values = mapOf(
            "error" to "expired_token",
            "error_description" to "The mfa_token has expired. Please start the authentication flow again."
        )
        val exception = MfaVerifyException(values, 401)

        assertThat(exception.getCode(), `is`("expired_token"))
        assertThat(exception.getDescription(), containsString("mfa_token has expired"))
        assertThat(exception.statusCode, `is`(401))
    }

    @Test
    public fun shouldMfaVerifyExceptionHandleInvalidBindingCode(): Unit {
        val values = mapOf(
            "error" to "invalid_binding_code",
            "error_description" to "The binding code is invalid"
        )
        val exception = MfaVerifyException(values, 403)

        assertThat(exception.getCode(), `is`("invalid_binding_code"))
        assertThat(exception.getDescription(), `is`("The binding code is invalid"))
    }

    @Test
    public fun shouldMfaVerifyExceptionHandleInvalidRecoveryCode(): Unit {
        val values = mapOf(
            "error" to "invalid_grant",
            "error_description" to "The recovery code is invalid"
        )
        val exception = MfaVerifyException(values, 403)

        assertThat(exception.getCode(), `is`("invalid_grant"))
        assertThat(exception.getDescription(), `is`("The recovery code is invalid"))
    }


    @Test
    public fun shouldAllExceptionsInheritFromMfaException(): Unit {
        val listException = MfaListAuthenticatorsException(emptyMap(), 400)
        val enrollException = MfaEnrollmentException(emptyMap(), 400)
        val challengeException = MfaChallengeException(emptyMap(), 400)
        val verifyException = MfaVerifyException(emptyMap(), 400)

        assertThat(listException, `is`(instanceOf(MfaException::class.java)))
        assertThat(enrollException, `is`(instanceOf(MfaException::class.java)))
        assertThat(challengeException, `is`(instanceOf(MfaException::class.java)))
        assertThat(verifyException, `is`(instanceOf(MfaException::class.java)))
    }

    @Test
    public fun shouldMfaExceptionInheritFromAuth0Exception(): Unit {
        val exception = MfaVerifyException(emptyMap(), 400)

        assertThat(exception, `is`(instanceOf(com.auth0.android.Auth0Exception::class.java)))
        assertThat(exception, `is`(instanceOf(Exception::class.java)))
    }


    @Test
    public fun shouldExceptionsReturnCorrectStatusCodes(): Unit {
        val exception400 = MfaVerifyException(emptyMap(), 400)
        val exception401 = MfaVerifyException(emptyMap(), 401)
        val exception403 = MfaVerifyException(emptyMap(), 403)
        val exception404 = MfaVerifyException(emptyMap(), 404)
        val exception500 = MfaVerifyException(emptyMap(), 500)

        assertThat(exception400.statusCode, `is`(400))
        assertThat(exception401.statusCode, `is`(401))
        assertThat(exception403.statusCode, `is`(403))
        assertThat(exception404.statusCode, `is`(404))
        assertThat(exception500.statusCode, `is`(500))
    }

    @Test
    public fun shouldExceptionHaveZeroStatusCodeByDefault(): Unit {
        val exception = MfaListAuthenticatorsException.invalidRequest("test")
        assertThat(exception.statusCode, `is`(0))
    }


    @Test
    public fun shouldExceptionMessageContainErrorCode(): Unit {
        val values = mapOf(
            "error" to "custom_error_code",
            "error_description" to "Description"
        )

        val listException = MfaListAuthenticatorsException(values, 400)
        val enrollException = MfaEnrollmentException(values, 400)
        val challengeException = MfaChallengeException(values, 400)
        val verifyException = MfaVerifyException(values, 400)

        assertThat(listException.message, containsString("custom_error_code"))
        assertThat(enrollException.message, containsString("custom_error_code"))
        assertThat(challengeException.message, containsString("custom_error_code"))
        assertThat(verifyException.message, containsString("custom_error_code"))
    }

}
