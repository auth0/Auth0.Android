package com.auth0.android.embedded

import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.util.EmbeddedAuthMockServer
import com.auth0.android.util.SSLTestUtils.testClient
import com.google.gson.reflect.TypeToken
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.containsInAnyOrder
import org.hamcrest.Matchers.hasEntry
import org.hamcrest.Matchers.hasItem
import org.hamcrest.Matchers.hasKey
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.not
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
public class EmbeddedAuthClientTest {

    private lateinit var mockAPI: EmbeddedAuthMockServer
    private lateinit var client: EmbeddedAuthClient

    private val auth0: Auth0
        get() {
            val auth0 = Auth0.getInstance(CLIENT_ID, mockAPI.domain, mockAPI.domain)
            auth0.networkingClient = testClient
            return auth0
        }

    @Before
    public fun setUp() {
        mockAPI = EmbeddedAuthMockServer()
        client = EmbeddedAuthClient(auth0)
    }

    @After
    public fun tearDown() {
        mockAPI.shutdown()
    }

    @Test
    public fun `discover should GET the discovery endpoint with the client id`() {
        mockAPI.willReturnEmptyDiscovery()

        client.discover().execute()

        val request = mockAPI.takeRequest()
        assertThat(request.method, `is`("GET"))
        assertThat(request.requestUrl?.encodedPath, `is`("/e/discovery"))
        assertThat(request.requestUrl?.queryParameter("client_id"), `is`(CLIENT_ID))
        assertThat(request.requestUrl?.queryParameter("connection"), `is`(nullValue()))
    }

    @Test
    public fun `discover should add the connection query parameter when given`() {
        mockAPI.willReturnEmptyDiscovery()

        client.discover("my-connection").execute()

        val request = mockAPI.takeRequest()
        assertThat(request.requestUrl?.queryParameter("connection"), `is`("my-connection"))
    }

    @Test
    public fun `discover should send the Auth0-Client header`() {
        mockAPI.willReturnEmptyDiscovery()

        client.discover().execute()

        val request = mockAPI.takeRequest()
        assertThat(request.getHeader("Auth0-Client"), `is`(notNullValue()))
    }

    @Test
    public fun `discover should parse a full response into a DiscoveryResult`() {
        mockAPI.willReturnFullDiscovery()

        val result = client.discover().execute()

        assertThat(
            result.types,
            containsInAnyOrder(
                GrantType.PASSWORD,
                GrantType.PASSWORD_REALM,
                GrantType.PASSKEY,
                GrantType.PASSWORDLESS_OTP,
                GrantType.NATIVE_SOCIAL,
                GrantType.AUTHORIZATION_CODE,
                GrantType.UNKNOWN
            )
        )
    }

    @Test
    public fun `discover should surface an empty body 404 as an embedded auth error`() {
        mockAPI.willReturnNotEnabled()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.code, `is`(Auth0Exception.EMPTY_BODY_ERROR))
        assertThat(error?.statusCode, `is`(404))
        assertThat(error?.isNetworkError, `is`(false))
    }

    @Test
    public fun `discover should surface a non JSON error body`() {
        mockAPI.willReturnPlainTextError()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.code, `is`(Auth0Exception.NON_JSON_ERROR))
        assertThat(error?.description, `is`(EmbeddedAuthMockServer.PLAIN_TEXT_ERROR))
        assertThat(error?.statusCode, `is`(500))
    }

    @Test
    public fun `discover should surface a JSON error envelope`() {
        mockAPI.willReturnJsonError()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.code, `is`(EmbeddedAuthMockServer.ERROR_CODE))
        assertThat(error?.description, `is`(EmbeddedAuthMockServer.ERROR_DESCRIPTION))
        assertThat(error?.statusCode, `is`(400))
    }

    @Test
    public fun `discover should surface a network failure as a network error`() {
        mockAPI.shutdown()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.isNetworkError, `is`(true))
    }

    @Test
    public fun `authorize should POST the authorize endpoint with client id and capabilities`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_IDENTIFY,
            EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL
        )

        try {
            client.authorize().execute()
        } catch (_: EmbeddedAuthException) {
            // Expected: the first step never completes the flow.
        }

        val request = mockAPI.takeRequest()
        assertThat(request.method, `is`("POST"))
        assertThat(request.requestUrl?.encodedPath, `is`("/e/authorize"))
        val body = bodyFromRequest<Any>(request)
        assertThat(body, hasEntry<String, Any>("client_id", CLIENT_ID))
        assertThat(body, hasKey("capabilities"))
        assertThat(body, not(hasKey("auth_session")))
        assertThat(body, not(hasKey("connection")))
    }

    @Test
    public fun `authorize should send the connection when given`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_IDENTIFY,
            EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL
        )

        try {
            client.authorize("my-connection").execute()
        } catch (_: EmbeddedAuthException) {
        }

        val body = bodyFromRequest<Any>(mockAPI.takeRequest())
        assertThat(body, hasEntry<String, Any>("connection", "my-connection"))
    }

    @Test
    public fun `authorize should surface the first step as an insufficient_authorization error`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_IDENTIFY,
            EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL
        )

        val error = executeExpectingError { client.authorize() }

        assertThat(error.code, `is`("insufficient_authorization"))
        assertThat(error.isInsufficientAuthorization, `is`(true))
        assertThat(error.statusCode, `is`(403))
        assertThat(error.nextActions.map { it.action }, hasItem(EmbeddedAction.IDENTIFY_EMAIL))
        assertThat(error.nextActions.map { it.action }, not(hasItem(EmbeddedAction.VERIFY_OTP)))
    }

    @Test
    public fun `continuation should carry the rotated auth_session and action, and drop client_id`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_IDENTIFY,
            EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL
        )
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_CHALLENGE,
            EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL
        )

        executeExpectingError { client.authorize() }
        executeExpectingError { client.identifyEmail("user@example.com") }

        mockAPI.takeRequest() // the authorize request
        val body = bodyFromRequest<Any>(mockAPI.takeRequest())
        assertThat(
            body,
            hasEntry<String, Any>("auth_session", EmbeddedAuthMockServer.SESSION_IDENTIFY)
        )
        assertThat(body, hasEntry<String, Any>("action", EmbeddedAction.IDENTIFY_EMAIL.value))
        assertThat(body, hasEntry<String, Any>("email", "user@example.com"))
        assertThat(body, not(hasKey("client_id")))
    }

    @Test
    public fun `full flow should exchange the authorization code for credentials`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_IDENTIFY,
            EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL
        )
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_CHALLENGE,
            EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL
        )
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_VERIFY,
            EmbeddedAuthMockServer.NEXT_VERIFY_OTP
        )
        mockAPI.willReturnAuthorizationCode()
        mockAPI.willReturnTokens()

        val identify = executeExpectingError { client.authorize() }
        assertThat(identify.nextActions.map { it.action }, hasItem(EmbeddedAction.IDENTIFY_EMAIL))

        val challenge = executeExpectingError { client.identifyEmail("user@example.com") }
        assertThat(challenge.nextActions.map { it.action }, hasItem(EmbeddedAction.CHALLENGE_EMAIL))

        val verify = executeExpectingError { client.challengeEmail() }
        assertThat(verify.nextActions.map { it.action }, hasItem(EmbeddedAction.VERIFY_OTP))

        val credentials = client.verifyOtp("123456").execute()

        assertThat(credentials, `is`(notNullValue()))
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))
    }

    @Test
    public fun `verifying the code should exchange the code at the token endpoint`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_VERIFY,
            EmbeddedAuthMockServer.NEXT_VERIFY_OTP
        )
        mockAPI.willReturnAuthorizationCode()
        mockAPI.willReturnTokens()

        // Prime the flow so a session is active for verifyOtp.
        primeVerifyStep()

        client.verifyOtp("123456").execute()

        mockAPI.takeRequest() // the priming authorize request
        mockAPI.takeRequest() // the verifyOtp authorize request
        val tokenRequest = mockAPI.takeRequest()
        assertThat(tokenRequest.method, `is`("POST"))
        assertThat(tokenRequest.requestUrl?.encodedPath, `is`("/oauth/token"))
        val body = bodyFromRequest<Any>(tokenRequest)
        assertThat(body, hasEntry<String, Any>("client_id", CLIENT_ID))
        assertThat(body, hasEntry<String, Any>("grant_type", "authorization_code"))
        assertThat(
            body,
            hasEntry<String, Any>("code", EmbeddedAuthMockServer.AUTHORIZATION_CODE)
        )
    }

    @Test
    public fun `a wrong code should re-offer the verify step and keep the flow alive`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_VERIFY,
            EmbeddedAuthMockServer.NEXT_VERIFY_OTP
        )
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_VERIFY,
            EmbeddedAuthMockServer.NEXT_VERIFY_OTP,
            description = "That code was invalid."
        )

        primeVerifyStep()

        val retry = executeExpectingError { client.verifyOtp("000000") }

        assertThat(retry.nextActions.map { it.action }, hasItem(EmbeddedAction.VERIFY_OTP))
        assertThat(retry.description, `is`("That code was invalid."))
    }

    @Test
    public fun `a terminal error should clear the session so continuation is rejected locally`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_IDENTIFY,
            EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL
        )
        mockAPI.willReturnAccessDenied()

        executeExpectingError { client.authorize() }
        val denied = executeExpectingError { client.identifyEmail("user@example.com") }
        assertThat(denied.code, `is`("access_denied"))
        assertThat(denied.isAccessDenied, `is`(true))
        assertThat(denied.nextActions.isEmpty(), `is`(true))

        // The flow is over; a further continuation must fail locally without a network call.
        val queuedBefore = mockAPI.server.requestCount
        val guard = executeExpectingError { client.challengeEmail() }
        assertThat(guard.code, `is`("no_active_session"))
        assertThat(guard.statusCode, `is`(0))
        assertThat(mockAPI.server.requestCount, `is`(queuedBefore))
    }

    @Test
    public fun `a failed token exchange keeps the session so the step can be retried`() {
        mockAPI.willReturnContinuation(
            EmbeddedAuthMockServer.SESSION_VERIFY,
            EmbeddedAuthMockServer.NEXT_VERIFY_OTP
        )
        mockAPI.willReturnAuthorizationCode()
        mockAPI.willReturnJsonError() // the /oauth/token exchange fails
        mockAPI.willReturnAuthorizationCode()
        mockAPI.willReturnTokens() // the retried exchange succeeds

        primeVerifyStep()

        // First attempt: the code is accepted but the token exchange fails.
        val exchangeError = executeExpectingError { client.verifyOtp("123456") }
        assertThat(exchangeError.code, `is`(EmbeddedAuthMockServer.ERROR_CODE))

        // The session survived, so retrying reaches the network (not a local no_active_session) and completes.
        val credentials = client.verifyOtp("123456").execute()
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))
    }

    @Test
    public fun `calling a continuation before authorize fails without a network call`() {
        val error = executeExpectingError { client.identifyEmail("user@example.com") }

        assertThat(error.code, `is`("no_active_session"))
        assertThat(error.statusCode, `is`(0))
        assertThat(mockAPI.server.requestCount, `is`(0))
    }

    /** Runs [request] to completion expecting it to fail, and returns the error. */
    private fun executeExpectingError(request: () -> com.auth0.android.request.Request<*, EmbeddedAuthException>): EmbeddedAuthException {
        return try {
            request().execute()
            throw AssertionError("Expected an EmbeddedAuthException but the request succeeded")
        } catch (ex: EmbeddedAuthException) {
            ex
        }
    }

    /** Advances the flow to the point where a code is expected. Enqueue a verify continuation first. */
    private fun primeVerifyStep() {
        executeExpectingError { client.authorize() }
    }

    private inline fun <reified T> bodyFromRequest(request: RecordedRequest): Map<String, T> {
        val mapType = object : TypeToken<Map<String, T>>() {}.type
        return GsonProvider.gson.fromJson(request.body.readUtf8(), mapType)
    }

    private companion object {
        private const val CLIENT_ID = "CLIENT_ID"
    }
}
