package com.auth0.android.myaccount

import com.auth0.android.Auth0
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.request.Response
import com.auth0.android.result.*
import com.auth0.android.util.MockMyAccountCallback
import com.auth0.android.util.MyAccountAPIMockServer
import com.auth0.android.util.SSLTestUtils.testClient
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.nhaarman.mockitokotlin2.mock
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.MockitoAnnotations
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
public class MyAccountAPIClientTest {

    private lateinit var client: MyAccountAPIClient
    private lateinit var gson: Gson
    private lateinit var mockAPI: MyAccountAPIMockServer

    @Before
    public fun setUp() {
        mockAPI = MyAccountAPIMockServer()
        MockitoAnnotations.openMocks(this)
        gson = GsonBuilder().serializeNulls().create()
        client = MyAccountAPIClient(auth0, ACCESS_TOKEN)
    }

    @After
    public fun tearDown() {
        mockAPI.shutdown()
    }

    @Test
    public fun `passkeyEnrollmentChallenge should build correct URL`() {
        val callback = MockMyAccountCallback<PasskeyEnrollmentChallenge>()
        client.passkeyEnrollmentChallenge()
            .start(callback)
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods"))
    }

    // ... (All other existing passkey tests remain here) ...

    @Test
    public fun `enroll should handle 400 bad request errors correctly`() {
        mockAPI.willReturnErrorForBadRequest()
        val enrollmentChallenge = PasskeyEnrollmentChallenge(
            authenticationMethodId = AUTHENTICATION_ID,
            authSession = AUTH_SESSION,
            authParamsPublicKey = mock()
        )

        lateinit var error: MyAccountException
        try {
            client.enroll(mockPublicKeyCredentials, enrollmentChallenge)
                .execute()
        } catch (e: MyAccountException) {
            error = e
        }

        val request = mockAPI.takeRequest()
        assertThat(
            request.path,
            Matchers.equalTo("/me/v1/authentication-methods/${AUTHENTICATION_ID}/verify")
        )
        assertThat(error, Matchers.notNullValue())
        assertThat(error.statusCode, Matchers.`is`(400))
        assertThat(error.message, Matchers.containsString("Bad Request"))
    }

    @Test
    public fun `getFactors should build correct URL and Authorization header`() {
        val callback = MockMyAccountCallback<Factors>()
        client.getFactors().start(callback)

        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/me/v1/factors"))
        assertThat(request.getHeader("Authorization"), Matchers.equalTo("Bearer $ACCESS_TOKEN"))
        assertThat(request.method, Matchers.equalTo("GET"))
    }

    @Test
    public fun `getAuthenticationMethods should build correct URL and Authorization header`() {
        val callback = MockMyAccountCallback<AuthenticationMethods>()
        client.getAuthenticationMethods().start(callback)

        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods"))
        assertThat(request.getHeader("Authorization"), Matchers.equalTo("Bearer $ACCESS_TOKEN"))
        assertThat(request.method, Matchers.equalTo("GET"))
    }

    @Test
    public fun `getAuthenticationMethodById should build correct URL and Authorization header`() {
        val callback = MockMyAccountCallback<AuthenticationMethod>()
        val methodId = "email|12345"
        client.getAuthenticationMethodById(methodId).start(callback)

        val request = mockAPI.takeRequest()
        // FIX: Assert against the URL-encoded path
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods/email%7C12345"))
        assertThat(request.getHeader("Authorization"), Matchers.equalTo("Bearer $ACCESS_TOKEN"))
        assertThat(request.method, Matchers.equalTo("GET"))
    }

    @Test
    public fun `deleteAuthenticationMethod should build correct URL and Authorization header`() {
        val callback = MockMyAccountCallback<Void?>()
        val methodId = "email|12345"
        client.deleteAuthenticationMethod(methodId).start(callback)

        val request = mockAPI.takeRequest()
        // FIX: Assert against the URL-encoded path
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods/email%7C12345"))
        assertThat(request.getHeader("Authorization"), Matchers.equalTo("Bearer $ACCESS_TOKEN"))
        assertThat(request.method, Matchers.equalTo("DELETE"))
    }

    @Test
    public fun `updateAuthenticationMethodById should build correct URL and payload`() {
        val callback = MockMyAccountCallback<AuthenticationMethod>()
        val methodId = "phone|12345"
        val name = "My Android Phone"
        val preferredMethod = "sms"
        client.updateAuthenticationMethodById(methodId, name, preferredMethod).start(callback)

        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<String>(request)
        // FIX: Assert against the URL-encoded path
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods/phone%7C12345"))
        assertThat(request.method, Matchers.equalTo("PATCH"))
        assertThat(body, Matchers.hasEntry("name", name as Any))
        assertThat(body, Matchers.hasEntry("preferred_authentication_method", preferredMethod as Any))
    }

    @Test
    public fun `enrollEmail should send correct payload`() {
        val callback = MockMyAccountCallback<EnrollmentChallenge>()
        val email = "test@example.com"
        client.enrollEmail(email).start(callback)

        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods"))
        assertThat(request.method, Matchers.equalTo("POST"))
        assertThat(body, Matchers.hasEntry("type", "email" as Any))
        assertThat(body, Matchers.hasEntry("email", email as Any))
    }

    @Test
    public fun `enrollPhone should send correct payload`() {
        val callback = MockMyAccountCallback<EnrollmentChallenge>()
        val phoneNumber = "+11234567890"
        client.enrollPhone(phoneNumber, "sms").start(callback)

        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods"))
        assertThat(request.method, Matchers.equalTo("POST"))
        assertThat(body, Matchers.hasEntry("type", "phone" as Any))
        assertThat(body, Matchers.hasEntry("phone_number", phoneNumber as Any))
        assertThat(body, Matchers.hasEntry("preferred_authentication_method", "sms" as Any))
    }

    @Test
    public fun `enrollTotp should send correct payload`() {
        val callback = MockMyAccountCallback<EnrollmentChallenge>()
        client.enrollTotp().start(callback)

        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods"))
        assertThat(request.method, Matchers.equalTo("POST"))
        assertThat(body, Matchers.hasEntry("type", "totp" as Any))
    }

    @Test
    public fun `verifyOtp should send correct payload`() {
        val callback = MockMyAccountCallback<AuthenticationMethod>()
        val methodId = "email|123"
        val otp = "123456"
        val session = "abc-def"
        client.verifyOtp(methodId, otp, session).start(callback)

        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<String>(request)
        // FIX: Assert against the URL-encoded path
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods/email%7C123/verify"))
        assertThat(request.method, Matchers.equalTo("POST"))
        assertThat(body, Matchers.hasEntry("otp_code", otp as Any))
        assertThat(body, Matchers.hasEntry("auth_session", session as Any))
    }

    @Test
    public fun `verify for push notifications should send correct payload`() {
        val callback = MockMyAccountCallback<AuthenticationMethod>()
        val methodId = "push|123"
        val session = "abc-def"
        client.verify(methodId, session).start(callback)

        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<String>(request)
        // FIX: Assert against the URL-encoded path
        assertThat(request.path, Matchers.equalTo("/me/v1/authentication-methods/push%7C123/verify"))
        assertThat(request.method, Matchers.equalTo("POST"))
        assertThat(body, Matchers.hasEntry("auth_session", session as Any))
        assertThat(body.containsKey("otp_code"), Matchers.`is`(false))
    }

    // Helper methods and constants
    private fun <T> bodyFromRequest(request: RecordedRequest): Map<String, T> {
        val mapType = object : TypeToken<Map<String?, T>?>() {}.type
        return gson.fromJson(request.body.readUtf8(), mapType)
    }

    private val auth0: Auth0
        get() {
            val auth0 = Auth0.getInstance(CLIENT_ID, mockAPI.domain, mockAPI.domain)
            auth0.networkingClient = testClient
            return auth0
        }

    private val mockPublicKeyCredentials = PublicKeyCredentials(
        id = "id",
        rawId = "rawId",
        type = "public-key",
        clientExtensionResults = mock(),
        response = Response(
            authenticatorData = "authenticatordaya",
            clientDataJSON = "eyJ0eXBlIjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLm9yZy93ZWJhdXRobi9jcmVhdGUiLCJjaGFsbGVuZ2UiOiJZMmhoYkd4bGJtZGxVbUZ1Wkc5dFFubDBaWE5GYm1OdlpHVmtTVzVDWVhObE5qUT0iLCJvcmlnaW4iOiJleGFtcGxlLmF1dGgwLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
            attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAI4b7RFy4MnMqD4jDtl8BCpE5vvDmQSMHjZ7xZHlKFYiAiEA0GC_QoOve_71eMHlWAzM-YzQdGfNEZVVx3m_cNCJXAZoYXV0aERhdGFYJKlzaWduYXR1cmVEYXRhX19fX19fX19fX19fX19fX19fX19fUKI",
            transports = listOf("str"),
            signature = "signature",
            userHandle = "user"
        ),
        authenticatorAttachment = "platform"
    )

    private companion object {
        private const val CLIENT_ID = "CLIENTID"
        private const val USER_IDENTITY = "user123"
        private const val CONNECTION = "passkey-connection"
        private const val ACCESS_TOKEN = "accessToken"
        private const val AUTHENTICATION_ID = "authId123"
        private const val AUTH_SESSION = "session456"
    }
}