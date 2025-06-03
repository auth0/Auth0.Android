package com.auth0.android.myaccount

import com.auth0.android.Auth0
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.request.Response
import com.auth0.android.result.PasskeyAuthenticationMethod
import com.auth0.android.result.PasskeyEnrollmentChallenge
import com.auth0.android.util.AuthenticationAPIMockServer.Companion.SESSION_ID
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
import java.util.Map


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

    @Test
    public fun `passkeyEnrollmentChallenge should include correct parameters`() {
        val callback = MockMyAccountCallback<PasskeyEnrollmentChallenge>()
        client.passkeyEnrollmentChallenge(userIdentity = USER_IDENTITY, connection = CONNECTION)
            .start(callback)
        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("type", "passkey"))
        assertThat(body, Matchers.hasEntry("identity_user_id", USER_IDENTITY))
        assertThat(body, Matchers.hasEntry("connection", CONNECTION))
    }


    @Test
    public fun `passkeyEnrollmentChallenge should include Authorization header`() {
        val callback = MockMyAccountCallback<PasskeyEnrollmentChallenge>()
        client.passkeyEnrollmentChallenge()
            .start(callback)

        val request = mockAPI.takeRequest()
        val header = request.getHeader("Authorization")

        assertThat(
            header, Matchers.`is`(
                "Bearer $ACCESS_TOKEN"
            )
        )
    }

    @Test
    public fun `passkeyEnrollmentChallenge should throw exception if Location header is missing`() {
        mockAPI.willReturnPasskeyChallengeWithoutHeader()
        var error: MyAccountException? = null
        try {
            client.passkeyEnrollmentChallenge()
                .execute()
        } catch (ex: MyAccountException) {
            error = ex
        }
        mockAPI.takeRequest()
        assertThat(error, Matchers.notNullValue())
        assertThat(error?.message, Matchers.`is`("Authentication ID not found"))
    }


    @Test
    public fun `passkeyEnrollmentChallenge should parse successful response with encoded authentication ID`() {
        mockAPI.willReturnPasskeyChallenge()
        val response = client.passkeyEnrollmentChallenge()
            .execute()
        mockAPI.takeRequest()
        assertThat(response, Matchers.`is`(Matchers.notNullValue()))
        assertThat(response.authSession, Matchers.comparesEqualTo(SESSION_ID))
        assertThat(response.authenticationMethodId, Matchers.comparesEqualTo("passkey|new"))
        assertThat(response.authParamsPublicKey.relyingParty.id, Matchers.comparesEqualTo("rpId"))
        assertThat(
            response.authParamsPublicKey.relyingParty.name,
            Matchers.comparesEqualTo("rpName")
        )
    }

    @Test
    public fun `enroll should build correct URL`() {
        val callback = MockMyAccountCallback<PasskeyAuthenticationMethod>()
        val enrollmentChallenge = PasskeyEnrollmentChallenge(
            authenticationMethodId = AUTHENTICATION_ID,
            authSession = AUTH_SESSION,
            authParamsPublicKey = mock()
        )

        client.enroll(mockPublicKeyCredentials, enrollmentChallenge)
            .start(callback)
        val request = mockAPI.takeRequest()
        assertThat(
            request.path,
            Matchers.equalTo("/me/v1/authentication-methods/${AUTHENTICATION_ID}/verify")
        )
    }

    @Test
    public fun `enroll should include correct parameters and authn_response`() {
        val callback = MockMyAccountCallback<PasskeyAuthenticationMethod>()
        val enrollmentChallenge = PasskeyEnrollmentChallenge(
            authenticationMethodId = AUTHENTICATION_ID,
            authSession = AUTH_SESSION,
            authParamsPublicKey = mock()
        )
        client.enroll(mockPublicKeyCredentials, enrollmentChallenge)
            .start(callback)
        val request = mockAPI.takeRequest()
        val body = bodyFromRequest<Any>(request)
        assertThat(body, Matchers.hasEntry("auth_session", AUTH_SESSION))
        val authnResponse = body["authn_response"] as Map<*, *>
        assertThat(authnResponse["authenticatorAttachment"], Matchers.`is`("platform"))
        assertThat(authnResponse["id"], Matchers.`is`("id"))
        assertThat(authnResponse["rawId"], Matchers.`is`("rawId"))
        assertThat(authnResponse["type"], Matchers.`is`("public-key"))

        val responseData = authnResponse["response"] as Map<*, *>
        assertThat(responseData.containsKey("clientDataJSON"), Matchers.`is`(true))
        assertThat(responseData.containsKey("attestationObject"), Matchers.`is`(true))
    }

    @Test
    public fun `enroll should include Authorization header`() {

        val callback = MockMyAccountCallback<PasskeyAuthenticationMethod>()
        val enrollmentChallenge = PasskeyEnrollmentChallenge(
            authenticationMethodId = AUTHENTICATION_ID,
            authSession = AUTH_SESSION,
            authParamsPublicKey = mock()
        )
        client.enroll(mockPublicKeyCredentials, enrollmentChallenge)
            .start(callback)

        val request = mockAPI.takeRequest()
        val header = request.getHeader("Authorization")

        assertThat(
            header, Matchers.`is`(
                "Bearer $ACCESS_TOKEN"
            )
        )
    }


    @Test
    public fun `enroll should return PasskeyAuthenticationMethod on success`() {
        mockAPI.willReturnPasskeyAuthenticationMethod()
        val enrollmentChallenge = PasskeyEnrollmentChallenge(
            authenticationMethodId = AUTHENTICATION_ID,
            authSession = AUTH_SESSION,
            authParamsPublicKey = mock()
        )
        val response = client.enroll(mockPublicKeyCredentials, enrollmentChallenge)
            .execute()
        mockAPI.takeRequest()
        assertThat(response, Matchers.`is`(Matchers.notNullValue()))
        assertThat(response.id, Matchers.comparesEqualTo("auth_method_123456789"))
        assertThat(response.type, Matchers.comparesEqualTo("passkey"))
        assertThat(response.credentialDeviceType, Matchers.comparesEqualTo("phone"))
        assertThat(response.credentialBackedUp, Matchers.comparesEqualTo(true))
        assertThat(response.publicKey, Matchers.comparesEqualTo("publickey"))
    }


    private fun <T> bodyFromRequest(request: RecordedRequest): kotlin.collections.Map<String, T> {
        val mapType = object : TypeToken<kotlin.collections.Map<String?, T>?>() {}.type
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


