package com.auth0.android.authentication

import android.content.Context
import com.auth0.android.Auth0
import com.auth0.android.authentication.passwordless.DeliveryMethod
import com.auth0.android.authentication.passwordless.PasswordlessClient
import com.auth0.android.dpop.DPoPKeyStore
import com.auth0.android.dpop.DPoPUtil
import com.auth0.android.dpop.FakeECPrivateKey
import com.auth0.android.dpop.FakeECPublicKey
import com.auth0.android.request.internal.ThreadSwitcherShadow
import com.auth0.android.result.Credentials
import com.auth0.android.result.PasswordlessChallenge
import com.auth0.android.util.SSLTestUtils
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.whenever
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.hasEntry
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ThreadSwitcherShadow::class])
@OptIn(ExperimentalCoroutinesApi::class)
public class PasswordlessClientTest {

    private lateinit var mockServer: MockWebServer
    private lateinit var auth0: Auth0
    private lateinit var passwordlessClient: PasswordlessClient
    private lateinit var gson: Gson
    private lateinit var mockKeyStore: DPoPKeyStore
    private lateinit var mockContext: Context

    @Before
    public fun setUp() {
        mockServer = SSLTestUtils.createMockWebServer()
        mockServer.start()
        val domain = mockServer.url("/").toString()
        auth0 = Auth0.getInstance(CLIENT_ID, domain, domain)
        auth0.networkingClient = SSLTestUtils.testClient
        passwordlessClient = PasswordlessClient(auth0)
        gson = GsonBuilder().serializeNulls().create()
        mockKeyStore = mock()
        mockContext = mock()
        whenever(mockContext.applicationContext).thenReturn(mockContext)
        DPoPUtil.keyStore = mockKeyStore
    }

    @After
    public fun tearDown() {
        mockServer.shutdown()
    }

    private fun enqueueMockResponse(json: String, statusCode: Int = 200) {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(statusCode)
                .addHeader("Content-Type", "application/json")
                .setBody(json)
        )
    }

    private fun enqueueErrorResponse(error: String, description: String, statusCode: Int = 400) {
        enqueueMockResponse("""{"error": "$error", "error_description": "$description"}""", statusCode)
    }

    private inline fun <reified T> bodyFromRequest(request: RecordedRequest): Map<String, T> {
        val mapType = object : TypeToken<Map<String, T>>() {}.type
        return gson.fromJson(request.body.readUtf8(), mapType)
    }

    @Test
    public fun shouldCreateClient() {
        assertThat(PasswordlessClient(auth0), `is`(notNullValue()))
    }

    @Test
    public fun shouldChallengeWithEmailHitOtpChallengeWithCorrectParams(): Unit = runTest {
        enqueueMockResponse("""{"auth_session": "session_abc"}""")

        val challenge = passwordlessClient
            .challengeWithEmail("user@example.com", CONNECTION, allowSignup = true)
            .await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/otp/challenge"))
        assertThat(request.method, `is`("POST"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, hasEntry("client_id", CLIENT_ID))
        assertThat(body, hasEntry("connection", CONNECTION))
        assertThat(body, hasEntry("email", "user@example.com"))
        assertThat(body, hasEntry("allow_signup", "true"))
        assertThat(challenge.authSession, `is`("session_abc"))
    }

    @Test
    public fun shouldChallengeWithEmailDefaultAllowSignupFalse(): Unit = runTest {
        enqueueMockResponse("""{"auth_session": "session_abc"}""")

        passwordlessClient.challengeWithEmail("user@example.com", CONNECTION).await()

        val body = bodyFromRequest<String>(mockServer.takeRequest())
        assertThat(body, hasEntry("allow_signup", "false"))
    }

    @Test
    public fun shouldChallengeWithPhoneNumberHitOtpChallengeWithCorrectParams(): Unit = runTest {
        enqueueMockResponse("""{"auth_session": "session_abc"}""")

        val challenge = passwordlessClient.challengeWithPhoneNumber(
            "+15555550123", CONNECTION, DeliveryMethod.VOICE, allowSignup = true
        ).await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/otp/challenge"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, hasEntry("client_id", CLIENT_ID))
        assertThat(body, hasEntry("connection", CONNECTION))
        assertThat(body, hasEntry("phone_number", "+15555550123"))
        assertThat(body, hasEntry("delivery_method", "voice"))
        assertThat(body, hasEntry("allow_signup", "true"))
        assertThat(challenge.authSession, `is`("session_abc"))
    }

    @Test
    public fun shouldChallengeWithPhoneNumberDefaultDeliveryMethodText(): Unit = runTest {
        enqueueMockResponse("""{"auth_session": "session_abc"}""")

        passwordlessClient.challengeWithPhoneNumber("+15555550123", CONNECTION).await()

        val body = bodyFromRequest<String>(mockServer.takeRequest())
        assertThat(body, hasEntry("delivery_method", "text"))
    }

    @Test
    public fun shouldIncludeAuth0ClientHeaderInChallenge(): Unit = runTest {
        enqueueMockResponse("""{"auth_session": "session_abc"}""")

        passwordlessClient.challengeWithEmail("user@example.com", CONNECTION).await()

        assertThat(mockServer.takeRequest().getHeader("Auth0-Client"), `is`(notNullValue()))
    }

    @Test
    public fun shouldPropagateChallengeApiError() {
        enqueueErrorResponse("invalid_connection", "Connection does not exist", 400)

        val exception = assertThrows(AuthenticationException::class.java) {
            runTest { passwordlessClient.challengeWithEmail("user@example.com", CONNECTION).await() }
        }
        assertThat(exception.getCode(), `is`("invalid_connection"))
    }

    @Test
    public fun shouldFailChallengeWithBlankEmailWithoutNetworkCall() {
        val exception = assertThrows(AuthenticationException::class.java) {
            runTest { passwordlessClient.challengeWithEmail("", CONNECTION).await() }
        }
        assertThat(exception.getCode(), `is`("invalid_request"))
        assertThat(exception.getDescription(), containsString("email is required"))
        assertThat(mockServer.requestCount, `is`(0))
    }

    @Test
    public fun shouldFailChallengeWithBlankConnectionWithoutNetworkCall() {
        val exception = assertThrows(AuthenticationException::class.java) {
            runTest { passwordlessClient.challengeWithEmail("user@example.com", "").await() }
        }
        assertThat(exception.getCode(), `is`("invalid_request"))
        assertThat(exception.getDescription(), containsString("connection is required"))
        assertThat(mockServer.requestCount, `is`(0))
    }

    @Test
    public fun shouldFailChallengeWithBlankPhoneWithoutNetworkCall() {
        val exception = assertThrows(AuthenticationException::class.java) {
            runTest { passwordlessClient.challengeWithPhoneNumber("", CONNECTION).await() }
        }
        assertThat(exception.getCode(), `is`("invalid_request"))
        assertThat(exception.getDescription(), containsString("phone_number is required"))
        assertThat(mockServer.requestCount, `is`(0))
    }

    @Test
    public fun shouldLoginWithOtpHitOauthTokenWithCorrectParams(): Unit = runTest {
        enqueueMockResponse(
            """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        )

        passwordlessClient.loginWithOTP(PasswordlessChallenge("session_abc"), "123456").await()

        val request = mockServer.takeRequest()
        assertThat(request.path, `is`("/oauth/token"))
        assertThat(request.method, `is`("POST"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, hasEntry("client_id", CLIENT_ID))
        assertThat(body, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/passwordless/otp"))
        assertThat(body, hasEntry("auth_session", "session_abc"))
        assertThat(body, hasEntry("otp", "123456"))
    }

    @Test
    public fun shouldLoginWithOtpReturnCredentials(): Unit = runTest {
        enqueueMockResponse(
            """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        )

        val credentials = passwordlessClient.loginWithOTP(PasswordlessChallenge("session_abc"), "123456").await()

        assertThat(credentials.accessToken, `is`(ACCESS_TOKEN))
    }

    @Test
    public fun shouldPropagateLoginWithOtpApiError() {
        enqueueErrorResponse("invalid_grant", "Invalid or expired code", 403)

        val exception = assertThrows(AuthenticationException::class.java) {
            runTest { passwordlessClient.loginWithOTP(PasswordlessChallenge("session_abc"), "000000").await() }
        }
        assertThat(exception.getCode(), `is`("invalid_grant"))
    }

    @Test
    public fun shouldFailLoginWithBlankOtpWithoutNetworkCall() {
        val exception = assertThrows(AuthenticationException::class.java) {
            runTest { passwordlessClient.loginWithOTP(PasswordlessChallenge("session_abc"), "").await() }
        }
        assertThat(exception.getCode(), `is`("invalid_request"))
        assertThat(exception.getDescription(), containsString("otp is required"))
        assertThat(mockServer.requestCount, `is`(0))
    }

    @Test
    public fun shouldAttachDpopHeaderOnLoginWhenDpopEnabled(): Unit = runTest {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(FakeECPrivateKey(), FakeECPublicKey()))
        val dpopClient = AuthenticationAPIClient(auth0).useDPoP(mockContext).passwordlessClient()
        enqueueMockResponse(
            """{"access_token": "$ACCESS_TOKEN", "id_token": "$ID_TOKEN", "token_type": "Bearer", "expires_in": 86400}"""
        )

        dpopClient.loginWithOTP(PasswordlessChallenge("session_abc"), "123456").await()

        val request = mockServer.takeRequest()
        assertThat(request.getHeader("DPoP"), `is`(notNullValue()))
    }

    @Test
    public fun shouldNotAttachDpopHeaderOnChallengeWhenDpopEnabled(): Unit = runTest {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(FakeECPrivateKey(), FakeECPublicKey()))
        val dpopClient = AuthenticationAPIClient(auth0).useDPoP(mockContext).passwordlessClient()
        enqueueMockResponse("""{"auth_session": "session_abc"}""")

        dpopClient.challengeWithEmail("user@example.com", CONNECTION).await()

        val request = mockServer.takeRequest()
        assertThat(request.getHeader("DPoP"), `is`(nullValue()))
    }

    private companion object {
        private const val CLIENT_ID = "CLIENT_ID"
        private const val CONNECTION = "Username-Password-Authentication"
        private const val ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.sig"
        private const val ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.sig"
    }
}
