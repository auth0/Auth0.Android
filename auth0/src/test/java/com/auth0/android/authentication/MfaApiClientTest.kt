package com.auth0.android.authentication

import com.auth0.android.Auth0
import com.auth0.android.authentication.mfa.MfaApiClient
import com.auth0.android.authentication.mfa.MfaEnrollmentType
import com.auth0.android.authentication.mfa.MfaVerificationType
import com.auth0.android.authentication.mfa.MfaException.*
import com.auth0.android.request.internal.ThreadSwitcherShadow
import com.auth0.android.result.Authenticator
import com.auth0.android.result.Challenge
import com.auth0.android.result.Credentials
import com.auth0.android.result.EnrollmentChallenge
import com.auth0.android.result.MfaEnrollmentChallenge
import com.auth0.android.result.TotpEnrollmentChallenge
import com.auth0.android.util.CallbackMatcher
import com.auth0.android.util.MockCallback
import com.auth0.android.util.SSLTestUtils
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.*
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLooper

@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ThreadSwitcherShadow::class])
@OptIn(ExperimentalCoroutinesApi::class)
public class MfaApiClientTest {

    private lateinit var mockServer: MockWebServer
    private lateinit var auth0: Auth0
    private lateinit var mfaClient: MfaApiClient
    private lateinit var gson: Gson

    @Before
    public fun setUp(): Unit {
        mockServer = SSLTestUtils.createMockWebServer()
        mockServer.start()
        val domain = mockServer.url("/").toString()
        auth0 = Auth0.getInstance(CLIENT_ID, domain, domain)
        auth0.networkingClient = SSLTestUtils.testClient
        mfaClient = MfaApiClient(auth0, MFA_TOKEN)
        gson = GsonBuilder().serializeNulls().create()
    }

    @After
    public fun tearDown(): Unit {
        mockServer.shutdown()
    }

    private fun enqueueMockResponse(json: String, statusCode: Int = 200): Unit {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(statusCode)
                .addHeader("Content-Type", "application/json")
                .setBody(json)
        )
    }

    private fun enqueueErrorResponse(error: String, description: String, statusCode: Int = 400): Unit {
        val json = """{"error": "$error", "error_description": "$description"}"""
        enqueueMockResponse(json, statusCode)
    }

    private inline fun <reified T> bodyFromRequest(request: RecordedRequest): Map<String, T> {
        val mapType = object : TypeToken<Map<String, T>>() {}.type
        return gson.fromJson(request.body.readUtf8(), mapType)
    }


    @Test
    public fun shouldCreateClientWithAuth0AndMfaToken(): Unit {
        val client = MfaApiClient(auth0, "test_mfa_token")
        assertThat(client, `is`(notNullValue()))
    }


    @Test
    public fun shouldGetAuthenticatorsSuccess(): Unit = runTest {
        val json = """[
            {"id": "sms|dev_123", "type": "oob", "authenticator_type": "oob", "active": true, "oob_channel": "sms"},
            {"id": "totp|dev_456", "type": "otp", "authenticator_type": "otp", "active": true}
        ]"""
        enqueueMockResponse(json)

        val authenticators = mfaClient.getAuthenticators(listOf("oob", "otp")).await()

        assertThat(authenticators, hasSize(2))
        assertThat(authenticators[0].id, `is`("sms|dev_123"))
        assertThat(authenticators[0].type, `is`("oob"))
        assertThat(authenticators[1].id, `is`("totp|dev_456"))
        assertThat(authenticators[1].type, `is`("otp"))
    }

    @Test
    public fun shouldFilterAuthenticatorsByFactorsAllowed(): Unit = runTest {
        val json = """[
            {"id": "sms|dev_123", "type": "oob", "authenticator_type": "oob", "active": true, "oob_channel": "sms"},
            {"id": "totp|dev_456", "type": "otp", "authenticator_type": "otp", "active": true},
            {"id": "recovery|dev_789", "type": "recovery-code", "authenticator_type": "recovery-code", "active": true}
        ]"""
        enqueueMockResponse(json)

        val authenticators = mfaClient.getAuthenticators(listOf("otp")).await()

        assertThat(authenticators, hasSize(1))
        assertThat(authenticators[0].id, `is`("totp|dev_456"))
        assertThat(authenticators[0].type, `is`("otp"))
    }

    @Test
    public fun shouldFailWithEmptyFactorsAllowed(): Unit {
        val exception = assertThrows(MfaListAuthenticatorsException::class.java) {
            runTest {
                mfaClient.getAuthenticators(emptyList()).await()
            }
        }
        assertThat(exception.getCode(), `is`("invalid_request"))
        assertThat(exception.getDescription(), containsString("factorsAllowed is required"))
    }

    @Test
    public fun shouldIncludeAuthorizationHeaderInGetAuthenticators(): Unit = runTest {
        val json = """[{"id": "sms|dev_123", "type": "oob", "active": true}]"""
        enqueueMockResponse(json)

        mfaClient.getAuthenticators(listOf("oob")).await()

        val request = mockServer.takeRequest()
        assertThat(request.getHeader("Authorization"), `is`("Bearer $MFA_TOKEN"))
        assertThat(request.path, `is`("/mfa/authenticators"))
        assertThat(request.method, `is`("GET"))
    }

    @Test
    public fun shouldHandleGetAuthenticatorsApiError(): Unit {
        enqueueErrorResponse("access_denied", "Invalid MFA token", 401)

        val exception = assertThrows(MfaListAuthenticatorsException::class.java) {
            runTest {
                mfaClient.getAuthenticators(listOf("oob")).await()
            }
        }
        assertThat(exception.getCode(), `is`("access_denied"))
        assertThat(exception.getDescription(), `is`("Invalid MFA token"))
        assertThat(exception.statusCode, `is`(401))
    }

    @Test
    public fun shouldReturnEmptyListWhenNoMatchingFactors(): Unit = runTest {
        val json = """[
            {"id": "sms|dev_123", "type": "oob", "active": true}
        ]"""
        enqueueMockResponse(json)

        val authenticators = mfaClient.getAuthenticators(listOf("otp")).await()

        assertThat(authenticators, hasSize(0))
    }

    @Test
    public fun shouldEnrollPhoneSuccess(): Unit = runTest {
        val json = """{
            "id": "sms|dev_123",
            "auth_session": "session_abc"
        }"""
        enqueueMockResponse(json)

        val challenge = mfaClient.enroll(MfaEnrollmentType.Phone("+12025550135")).await()

        assertThat(challenge, `is`(notNullValue()))
        assertThat(challenge.id, `is`("sms|dev_123"))
        assertThat(challenge.authSession, `is`("session_abc"))
    }

    @Test
    public fun shouldEnrollPhoneWithCorrectParameters(): Unit = runTest {
        val json = """{"id": "sms|dev_123", "auth_session": "session_abc"}"""
        enqueueMockResponse(json)

        mfaClient.enroll(MfaEnrollmentType.Phone("+12025550135")).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/mfa/associate"))
        assertThat(request.method, `is`("POST"))
        assertThat(request.getHeader("Authorization"), `is`("Bearer $MFA_TOKEN"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["authenticator_types"], `is`(listOf("oob")))
        assertThat(body["oob_channels"], `is`(listOf("sms")))
        assertThat(body["phone_number"], `is`("+12025550135"))
    }

    @Test
    public fun shouldEnrollPhoneFailure(): Unit {
        enqueueErrorResponse("invalid_phone", "Invalid phone number format", 400)

        val exception = assertThrows(MfaEnrollmentException::class.java) {
            runTest {
                mfaClient.enroll(MfaEnrollmentType.Phone("invalid")).await()
            }
        }
        assertThat(exception.getCode(), `is`("invalid_phone"))
        assertThat(exception.getDescription(), `is`("Invalid phone number format"))
    }


    @Test
    public fun shouldEnrollEmailSuccess(): Unit = runTest {
        val json = """{
            "id": "email|dev_456",
            "auth_session": "session_def"
        }"""
        enqueueMockResponse(json)

        val challenge = mfaClient.enroll(MfaEnrollmentType.Email("user@example.com")).await()

        assertThat(challenge, `is`(notNullValue()))
        assertThat(challenge.id, `is`("email|dev_456"))
        assertThat(challenge.authSession, `is`("session_def"))
    }

    @Test
    public fun shouldEnrollEmailWithCorrectParameters(): Unit = runTest {
        val json = """{"id": "email|dev_456", "auth_session": "session_def"}"""
        enqueueMockResponse(json)

        mfaClient.enroll(MfaEnrollmentType.Email("user@example.com")).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/mfa/associate"))
        assertThat(request.method, `is`("POST"))
        assertThat(request.getHeader("Authorization"), `is`("Bearer $MFA_TOKEN"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["authenticator_types"], `is`(listOf("oob")))
        assertThat(body["oob_channels"], `is`(listOf("email")))
        assertThat(body["email"], `is`("user@example.com"))
    }

    @Test
    public fun shouldEnrollEmailFailure(): Unit {
        enqueueErrorResponse("invalid_email", "Invalid email address", 400)

        val exception = assertThrows(MfaEnrollmentException::class.java) {
            runTest {
                mfaClient.enroll(MfaEnrollmentType.Email("invalid")).await()
            }
        }
        assertThat(exception.getCode(), `is`("invalid_email"))
        assertThat(exception.getDescription(), `is`("Invalid email address"))
    }


    @Test
    public fun shouldEnrollOtpSuccess(): Unit = runTest {
        val json = """{
            "id": "totp|dev_789",
            "auth_session": "session_ghi",
            "barcode_uri": "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
            "manual_input_code": "JBSWY3DPEHPK3PXP"
        }"""
        enqueueMockResponse(json)

        val challenge = mfaClient.enroll(MfaEnrollmentType.Otp).await()

        assertThat(challenge, `is`(instanceOf(TotpEnrollmentChallenge::class.java)))
        val totpChallenge = challenge as TotpEnrollmentChallenge
        assertThat(totpChallenge.id, `is`("totp|dev_789"))
        assertThat(totpChallenge.authSession, `is`("session_ghi"))
        assertThat(totpChallenge.barcodeUri, containsString("otpauth://"))
        assertThat(totpChallenge.manualInputCode, `is`("JBSWY3DPEHPK3PXP"))
    }

    @Test
    public fun shouldEnrollOtpWithCorrectParameters(): Unit = runTest {
        val json = """{
            "id": "totp|dev_789",
            "auth_session": "session_ghi",
            "barcode_uri": "otpauth://totp/test",
            "manual_input_code": "SECRET"
        }"""
        enqueueMockResponse(json)

        mfaClient.enroll(MfaEnrollmentType.Otp).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/mfa/associate"))
        assertThat(request.method, `is`("POST"))
        assertThat(request.getHeader("Authorization"), `is`("Bearer $MFA_TOKEN"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["authenticator_types"], `is`(listOf("otp")))
    }

    @Test
    public fun shouldEnrollOtpFailure(): Unit {
        enqueueErrorResponse("enrollment_failed", "OTP enrollment failed", 400)

        val exception = assertThrows(MfaEnrollmentException::class.java) {
            runTest {
                mfaClient.enroll(MfaEnrollmentType.Otp).await()
            }
        }
        assertThat(exception.getCode(), `is`("enrollment_failed"))
        assertThat(exception.getDescription(), `is`("OTP enrollment failed"))
    }


    @Test
    public fun shouldEnrollPushSuccess(): Unit = runTest {
        val json = """{
            "id": "push|dev_abc",
            "auth_session": "session_jkl"
        }"""
        enqueueMockResponse(json)

        val challenge = mfaClient.enroll(MfaEnrollmentType.Push).await()

        assertThat(challenge, `is`(notNullValue()))
        assertThat(challenge.id, `is`("push|dev_abc"))
        assertThat(challenge.authSession, `is`("session_jkl"))
    }

    @Test
    public fun shouldEnrollPushWithAuth0Channel(): Unit = runTest {
        val json = """{"id": "push|dev_abc", "auth_session": "session_jkl"}"""
        enqueueMockResponse(json)

        mfaClient.enroll(MfaEnrollmentType.Push).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/mfa/associate"))
        assertThat(request.method, `is`("POST"))
        assertThat(request.getHeader("Authorization"), `is`("Bearer $MFA_TOKEN"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["authenticator_types"], `is`(listOf("oob")))
        assertThat(body["oob_channels"], `is`(listOf("auth0")))
    }

    @Test
    public fun shouldEnrollPushFailure(): Unit {
        enqueueErrorResponse("enrollment_failed", "Push enrollment failed", 400)

        val exception = assertThrows(MfaEnrollmentException::class.java) {
            runTest {
                mfaClient.enroll(MfaEnrollmentType.Push).await()
            }
        }
        assertThat(exception.getCode(), `is`("enrollment_failed"))
        assertThat(exception.getDescription(), `is`("Push enrollment failed"))
    }


    @Test
    public fun shouldChallengeSuccess(): Unit = runTest {
        val json = """{
            "challenge_type": "oob",
            "oob_code": "oob_code_123",
            "binding_method": "prompt"
        }"""
        enqueueMockResponse(json)

        val challenge = mfaClient.challenge("sms|dev_123").await()

        assertThat(challenge, `is`(notNullValue()))
        assertThat(challenge.challengeType, `is`("oob"))
        assertThat(challenge.oobCode, `is`("oob_code_123"))
        assertThat(challenge.bindingMethod, `is`("prompt"))
    }

    @Test
    public fun shouldChallengeWithCorrectParameters(): Unit = runTest {
        val json = """{"challenge_type": "oob", "oob_code": "oob_123"}"""
        enqueueMockResponse(json)

        mfaClient.challenge("sms|dev_123").await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/mfa/challenge"))
        assertThat(request.method, `is`("POST"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["client_id"], `is`(CLIENT_ID))
        assertThat(body["mfa_token"], `is`(MFA_TOKEN))
        assertThat(body["challenge_type"], `is`("oob"))
        assertThat(body["authenticator_id"], `is`("sms|dev_123"))
    }

    @Test
    public fun shouldChallengeFailure(): Unit {
        enqueueErrorResponse("invalid_authenticator", "Authenticator not found", 404)

        val exception = assertThrows(MfaChallengeException::class.java) {
            runTest {
                mfaClient.challenge("invalid|dev").await()
            }
        }
        assertThat(exception.getCode(), `is`("invalid_authenticator"))
        assertThat(exception.getDescription(), `is`("Authenticator not found"))
        assertThat(exception.statusCode, `is`(404))
    }


    @Test
    public fun shouldVerifyOtpSuccess(): Unit = runTest {
        val json = """{
            "access_token": "$ACCESS_TOKEN",
            "id_token": "$ID_TOKEN",
            "refresh_token": "$REFRESH_TOKEN",
            "token_type": "Bearer",
            "expires_in": 86400
        }"""
        enqueueMockResponse(json)

        val credentials = mfaClient.verify(MfaVerificationType.Otp("123456")).await()

        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.accessToken, `is`(ACCESS_TOKEN))
        assertThat(credentials.idToken, `is`(ID_TOKEN))
        assertThat(credentials.refreshToken, `is`(REFRESH_TOKEN))
    }

    @Test
    public fun shouldVerifyOtpWithCorrectGrantType(): Unit = runTest {
        val json = """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        enqueueMockResponse(json)

        mfaClient.verify(MfaVerificationType.Otp("123456")).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/oauth/token"))
        assertThat(request.method, `is`("POST"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["client_id"], `is`(CLIENT_ID))
        assertThat(body["mfa_token"], `is`(MFA_TOKEN))
        assertThat(body["grant_type"], `is`("http://auth0.com/oauth/grant-type/mfa-otp"))
        assertThat(body["otp"], `is`("123456"))
    }

    @Test
    public fun shouldVerifyOtpFailWithInvalidCode(): Unit {
        enqueueErrorResponse("invalid_grant", "Invalid OTP code", 403)

        val exception = assertThrows(MfaVerifyException::class.java) {
            runTest {
                mfaClient.verify(MfaVerificationType.Otp("000000")).await()
            }
        }
        assertThat(exception.getCode(), `is`("invalid_grant"))
        assertThat(exception.getDescription(), `is`("Invalid OTP code"))
    }

    @Test
    public fun shouldVerifyOtpFailWithExpiredToken(): Unit {
        enqueueErrorResponse("expired_token", "MFA token has expired", 401)

        val exception = assertThrows(MfaVerifyException::class.java) {
            runTest {
                mfaClient.verify(MfaVerificationType.Otp("123456")).await()
            }
        }
        assertThat(exception.getCode(), `is`("expired_token"))
        assertThat(exception.getDescription(), `is`("MFA token has expired"))
        assertThat(exception.statusCode, `is`(401))
    }


    @Test
    public fun shouldVerifyOobWithBindingCodeSuccess(): Unit = runTest {
        val json = """{
            "access_token": "$ACCESS_TOKEN",
            "id_token": "$ID_TOKEN",
            "token_type": "Bearer",
            "expires_in": 86400
        }"""
        enqueueMockResponse(json)

        val credentials = mfaClient.verify(
            MfaVerificationType.Oob(oobCode = "oob_code_123", bindingCode = "654321")
        ).await()

        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.accessToken, `is`(ACCESS_TOKEN))
    }

    @Test
    public fun shouldVerifyOobWithoutBindingCodeSuccess(): Unit = runTest {
        val json = """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        enqueueMockResponse(json)

        val credentials = mfaClient.verify(MfaVerificationType.Oob(oobCode = "oob_code_123")).await()

        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.accessToken, `is`(ACCESS_TOKEN))
    }

    @Test
    public fun shouldVerifyOobWithCorrectParameters(): Unit = runTest {
        val json = """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        enqueueMockResponse(json)

        mfaClient.verify(MfaVerificationType.Oob(oobCode = "oob_code_123", bindingCode = "654321")).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/oauth/token"))
        assertThat(request.method, `is`("POST"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["client_id"], `is`(CLIENT_ID))
        assertThat(body["mfa_token"], `is`(MFA_TOKEN))
        assertThat(body["grant_type"], `is`("http://auth0.com/oauth/grant-type/mfa-oob"))
        assertThat(body["oob_code"], `is`("oob_code_123"))
        assertThat(body["binding_code"], `is`("654321"))
    }

    @Test
    public fun shouldVerifyOobWithoutBindingCodeInRequest(): Unit = runTest {
        val json = """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        enqueueMockResponse(json)

        mfaClient.verify(MfaVerificationType.Oob(oobCode = "oob_code_123")).await()

        val request = mockServer.takeRequest()
        val body = bodyFromRequest<Any>(request)
        assertThat(body.containsKey("binding_code"), `is`(false))
    }

    @Test
    public fun shouldVerifyOobFailure(): Unit {
        enqueueErrorResponse("invalid_grant", "Invalid OOB code", 403)

        val exception = assertThrows(MfaVerifyException::class.java) {
            runTest {
                mfaClient.verify(MfaVerificationType.Oob(oobCode = "invalid")).await()
            }
        }
        assertThat(exception.getCode(), `is`("invalid_grant"))
        assertThat(exception.getDescription(), `is`("Invalid OOB code"))
    }


    @Test
    public fun shouldVerifyRecoveryCodeSuccess(): Unit = runTest {
        val json = """{
            "access_token": "$ACCESS_TOKEN",
            "id_token": "$ID_TOKEN",
            "token_type": "Bearer",
            "expires_in": 86400,
            "recovery_code": "NEW_RECOVERY_CODE_123"
        }"""
        enqueueMockResponse(json)

        val credentials = mfaClient.verify(MfaVerificationType.RecoveryCode("OLD_RECOVERY_CODE")).await()

        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.accessToken, `is`(ACCESS_TOKEN))
        assertThat(credentials.recoveryCode, `is`("NEW_RECOVERY_CODE_123"))
    }

    @Test
    public fun shouldVerifyRecoveryCodeWithCorrectParameters(): Unit = runTest {
        val json = """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        enqueueMockResponse(json)

        mfaClient.verify(MfaVerificationType.RecoveryCode("RECOVERY_123")).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/oauth/token"))
        assertThat(request.method, `is`("POST"))

        val body = bodyFromRequest<Any>(request)
        assertThat(body["client_id"], `is`(CLIENT_ID))
        assertThat(body["mfa_token"], `is`(MFA_TOKEN))
        assertThat(body["grant_type"], `is`("http://auth0.com/oauth/grant-type/mfa-recovery-code"))
        assertThat(body["recovery_code"], `is`("RECOVERY_123"))
    }

    @Test
    public fun shouldVerifyRecoveryCodeFailWithInvalidCode(): Unit {
        enqueueErrorResponse("invalid_grant", "Invalid recovery code", 403)

        val exception = assertThrows(MfaVerifyException::class.java) {
            runTest {
                mfaClient.verify(MfaVerificationType.RecoveryCode("INVALID_CODE")).await()
            }
        }
        assertThat(exception.getCode(), `is`("invalid_grant"))
        assertThat(exception.getDescription(), `is`("Invalid recovery code"))
    }

    @Test
    public fun shouldVerifyRecoveryCodeFailWithExpiredToken(): Unit {
        enqueueErrorResponse("expired_token", "MFA token has expired", 401)

        val exception = assertThrows(MfaVerifyException::class.java) {
            runTest {
                mfaClient.verify(MfaVerificationType.RecoveryCode("RECOVERY_CODE")).await()
            }
        }
        assertThat(exception.getCode(), `is`("expired_token"))
        assertThat(exception.getDescription(), `is`("MFA token has expired"))
        assertThat(exception.statusCode, `is`(401))
    }


    @Test
    public fun shouldGetAuthenticatorsWithCallback(): Unit {
        val json = """[{"id": "sms|dev_123", "authenticator_type": "oob", "active": true}]"""
        enqueueMockResponse(json)

        val callback = MockCallback<List<Authenticator>, MfaListAuthenticatorsException>()

        mfaClient.getAuthenticators(listOf("oob"))
            .start(callback)

        ShadowLooper.idleMainLooper()

        assertThat(callback.getPayload(), `is`(notNullValue()))
        assertThat(callback.getPayload(), hasSize(1))
        assertThat(callback.getError(), `is`(nullValue()))
    }

    @Test
    public fun shouldEnrollPhoneWithCallback(): Unit {
        val json = """{"id": "sms|dev_123", "auth_session": "session_abc"}"""
        enqueueMockResponse(json)

        val callback = MockCallback<EnrollmentChallenge, MfaEnrollmentException>()

        mfaClient.enroll(MfaEnrollmentType.Phone("+12025550135"))
            .start(callback)

        ShadowLooper.idleMainLooper()

        assertThat(callback.getPayload(), `is`(notNullValue()))
        assertThat(callback.getPayload().id, `is`("sms|dev_123"))
        assertThat(callback.getError(), `is`(nullValue()))
    }

    @Test
    public fun shouldChallengeWithCallback(): Unit {
        val json = """{"challenge_type": "oob", "oob_code": "oob_123"}"""
        enqueueMockResponse(json)

        val callback = MockCallback<Challenge, MfaChallengeException>()

        mfaClient.challenge("sms|dev_123")
            .start(callback)

        ShadowLooper.idleMainLooper()

        assertThat(callback.getPayload(), `is`(notNullValue()))
        assertThat(callback.getPayload().challengeType, `is`("oob"))
        assertThat(callback.getError(), `is`(nullValue()))
    }

    @Test
    public fun shouldVerifyOtpWithCallback(): Unit {
        val json = """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        enqueueMockResponse(json)

        val callback = MockCallback<Credentials, MfaVerifyException>()

        mfaClient.verify(MfaVerificationType.Otp("123456"))
            .start(callback)

        ShadowLooper.idleMainLooper()

        assertThat(callback.getPayload(), `is`(notNullValue()))
        assertThat(callback.getPayload().accessToken, `is`(ACCESS_TOKEN))
        assertThat(callback.getError(), `is`(nullValue()))
    }


    @Test
    public fun shouldMfaListAuthenticatorsExceptionParseValues(): Unit {
        val values = mapOf(
            "error" to "access_denied",
            "error_description" to "Access denied",
            "custom_field" to "custom_value"
        )
        val exception = MfaListAuthenticatorsException(values, 403)

        assertThat(exception.getCode(), `is`("access_denied"))
        assertThat(exception.getDescription(), `is`("Access denied"))
        assertThat(exception.statusCode, `is`(403))
        assertThat(exception.getValue("custom_field"), `is`("custom_value"))
    }

    @Test
    public fun shouldMfaEnrollmentExceptionParseValues(): Unit {
        val values = mapOf(
            "error" to "enrollment_failed",
            "error_description" to "Enrollment failed"
        )
        val exception = MfaEnrollmentException(values, 400)

        assertThat(exception.getCode(), `is`("enrollment_failed"))
        assertThat(exception.getDescription(), `is`("Enrollment failed"))
        assertThat(exception.statusCode, `is`(400))
    }

    @Test
    public fun shouldMfaChallengeExceptionParseValues(): Unit {
        val values = mapOf(
            "error" to "invalid_authenticator",
            "error_description" to "Authenticator not found"
        )
        val exception = MfaChallengeException(values, 404)

        assertThat(exception.getCode(), `is`("invalid_authenticator"))
        assertThat(exception.getDescription(), `is`("Authenticator not found"))
        assertThat(exception.statusCode, `is`(404))
    }

    @Test
    public fun shouldMfaVerifyExceptionParseValues(): Unit {
        val values = mapOf(
            "error" to "invalid_grant",
            "error_description" to "Invalid code"
        )
        val exception = MfaVerifyException(values, 403)

        assertThat(exception.getCode(), `is`("invalid_grant"))
        assertThat(exception.getDescription(), `is`("Invalid code"))
        assertThat(exception.statusCode, `is`(403))
    }

    @Test
    public fun shouldExceptionUseUnknownErrorWhenNoErrorCode(): Unit {
        val values = mapOf("error_description" to "Something went wrong")
        val exception = MfaVerifyException(values, 500)

        assertThat(exception.getCode(), `is`("a0.sdk.internal_error.unknown"))
        assertThat(exception.getDescription(), `is`("Something went wrong"))
    }

    @Test
    public fun shouldExceptionUseDefaultDescriptionWhenNoDescription(): Unit {
        val values = mapOf("error" to "unknown_error")
        val exception = MfaVerifyException(values, 500)

        assertThat(exception.getCode(), `is`("unknown_error"))
        assertThat(exception.getDescription(), `is`("Failed to verify MFA code"))
    }


    private companion object {
        private const val CLIENT_ID = "CLIENT_ID"
        private const val MFA_TOKEN = "MFA_TOKEN_123"
        private const val ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        private const val ID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"
        private const val REFRESH_TOKEN = "REFRESH_TOKEN"
    }
}
