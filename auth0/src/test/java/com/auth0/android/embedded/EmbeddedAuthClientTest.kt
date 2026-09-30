package com.auth0.android.embedded

import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.embedded.authorize.IdentifierType
import com.auth0.android.embedded.authorize.NextAction
import com.auth0.android.embedded.authorize.OtpChannel
import com.auth0.android.embedded.authorize.OtpType
import com.auth0.android.embedded.discovery.GrantType
import com.auth0.android.util.EmbeddedAuthMockServer
import com.auth0.android.util.SSLTestUtils.testClient
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.containsInAnyOrder
import org.hamcrest.Matchers.empty
import org.hamcrest.Matchers.not
import org.hamcrest.Matchers.hasSize
import org.hamcrest.Matchers.instanceOf
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue
import org.json.JSONObject
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
    public fun `discover await should parse a full response into a DiscoveryResult`(): Unit =
        runTest {
            mockAPI.willReturnFullDiscovery()

            val result = client.discover().await()

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
    public fun `authorize should POST the authorize endpoint with the default scope and no audience`() {
        mockAPI.willReturnJsonError()

        try {
            client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute()
        } catch (_: EmbeddedAuthException) {
            // authorize always completes through a failure; we only inspect the request here.
        }

        val request = mockAPI.takeRequest()
        assertThat(request.method, `is`("POST"))
        assertThat(request.requestUrl?.encodedPath, `is`("/e/authorize"))
        val body = bodyOf(request)
        assertThat(body.getString("client_id"), `is`(CLIENT_ID))
        assertThat(body.getString("connection"), `is`(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION))
        assertThat(body.getString("scope"), `is`("openid profile email offline_access"))
        assertThat(body.has("audience"), `is`(false))
    }

    @Test
    public fun `authorize should send the given scope and audience`() {
        mockAPI.willReturnJsonError()

        try {
            client.authorize(
                connection = EmbeddedAuthMockServer.AUTHORIZE_CONNECTION,
                scope = "openid offline_access",
                audience = "https://api.example.com"
            ).execute()
        } catch (_: EmbeddedAuthException) {
        }

        val body = bodyOf(mockAPI.takeRequest())
        assertThat(body.getString("scope"), `is`("openid offline_access"))
        assertThat(body.getString("audience"), `is`("https://api.example.com"))
    }

    @Test
    public fun `verifyOtp should exchange the code and return credentials with an id token`() {
        // Establish a session, then run the terminal step through the token exchange.
        mockAPI.willReturnInsufficientAuthorization()
        try {
            client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute()
        } catch (_: EmbeddedAuthException) {
        }
        mockAPI.takeRequest()

        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()

        val credentials = client.verifyOtp("123456", OtpType.OOB).execute()

        assertThat(credentials.idToken, `is`(EmbeddedAuthMockServer.ID_TOKEN))
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))

        // The verify step posts to /e/authorize; the exchange posts to /oauth/token.
        mockAPI.takeRequest()
        val tokenRequest = mockAPI.takeRequest()
        assertThat(tokenRequest.requestUrl?.encodedPath, `is`("/oauth/token"))
        val tokenBody = bodyOf(tokenRequest)
        assertThat(tokenBody.getString("grant_type"), `is`("authorization_code"))
        assertThat(tokenBody.getString("code"), `is`(EmbeddedAuthMockServer.AUTHORIZATION_CODE))
    }

    @Test
    public fun `verifyOtp should surface a token response without an id token as an error`() {
        mockAPI.willReturnInsufficientAuthorization()
        try {
            client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute()
        } catch (_: EmbeddedAuthException) {
        }
        mockAPI.takeRequest()

        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokensWithoutIdToken()

        var error: EmbeddedAuthException? = null
        try {
            client.verifyOtp("123456", OtpType.OOB).execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
    }


    @Test
    public fun `identify with email should fail with no_active_session when no flow is in progress`() {
        val error = assertEmbeddedError { client.identify("jane@example.com", IdentifierType.EMAIL).execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    @Test
    public fun `identify with email should POST the authorize endpoint with the correct action and email`() {
        establishSession()
        mockAPI.willReturnInsufficientAuthorization()

        try {
            client.identify("jane@example.com", IdentifierType.EMAIL).execute()
        } catch (_: EmbeddedAuthException) {
        }

        val request = mockAPI.takeRequest()
        val body = bodyOf(request)
        assertThat(request.requestUrl?.encodedPath, `is`("/e/authorize"))
        assertThat(body.getString("action"), `is`("action:identify:email:v1"))
        assertThat(body.getString("email"), `is`("jane@example.com"))
        assertThat(body.getString("auth_session"), `is`(EmbeddedAuthMockServer.AUTH_SESSION))
    }



    @Test
    public fun `challengeEmail should fail with no_active_session when no flow is in progress`() {
        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    @Test
    public fun `challengeEmail should POST the authorize endpoint with the correct action and default index`() {
        establishSession()
        mockAPI.willReturnInsufficientAuthorization()

        try {
            client.challengeEmail().execute()
        } catch (_: EmbeddedAuthException) {
        }

        val body = bodyOf(mockAPI.takeRequest())
        assertThat(body.getString("action"), `is`("action:challenge:email:v1"))
        assertThat(body.getInt("index"), `is`(0))
    }

    @Test
    public fun `challengeEmail should POST the given index`() {
        establishSession()
        mockAPI.willReturnInsufficientAuthorization()

        try {
            client.challengeEmail(index = 2).execute()
        } catch (_: EmbeddedAuthException) {
        }

        assertThat(bodyOf(mockAPI.takeRequest()).getInt("index"), `is`(2))
    }



    @Test
    public fun `verifyOtp should fail with no_active_session when no flow is in progress`() {
        val error = assertEmbeddedError { client.verifyOtp("123456").execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    @Test
    public fun `verifyOtp should POST the correct action, otp, and type`() {
        establishSession()
        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()

        client.verifyOtp("654321", OtpType.TOTP).execute()

        val body = bodyOf(mockAPI.takeRequest())
        assertThat(body.getString("action"), `is`("action:verify:otp:v1"))
        assertThat(body.getString("otp"), `is`("654321"))
        assertThat(body.getString("type"), `is`("totp"))
    }



    @Test
    public fun `authorize continuation sets isInsufficientAuthorization and populates nextActions`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.isInsufficientAuthorization, `is`(true))
        assertThat(error.nextActions, hasSize(1))
        assertThat(error.nextActions[0], instanceOf(NextAction.IdentifyEmail::class.java))
    }

    @Test
    public fun `authorize continuation surfaces IdentifyPhone next action`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_IDENTIFY_PHONE)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.nextActions[0], instanceOf(NextAction.IdentifyPhone::class.java))
    }

    @Test
    public fun `authorize continuation surfaces ChallengeEmail with index and identifier`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        val action = error.nextActions[0] as NextAction.ChallengeEmail
        assertThat(action.index, `is`(1))
        assertThat(action.identifier, `is`(EmbeddedAuthMockServer.IDENTIFIER))
    }

    @Test
    public fun `authorize continuation surfaces VerifyOtp with channel and identifier`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        val action = error.nextActions[0] as NextAction.VerifyOtp
        assertThat(action.channel, `is`(OtpChannel.EMAIL))
        assertThat(action.identifier, `is`(EmbeddedAuthMockServer.IDENTIFIER))
    }

    @Test
    public fun `authorize continuation drops a VerifyOtp action with an unrecognised channel`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP_UNKNOWN_CHANNEL)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.nextActions, `is`(empty()))
    }

    @Test
    public fun `authorize continuation drops a VerifyOtp action without a channel`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP_NO_CHANNEL)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.nextActions, `is`(empty()))
    }

    @Test
    public fun `authorize continuation drops a ChallengeEmail action without an identifier`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL_NO_IDENTIFIER)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.nextActions, `is`(empty()))
    }

    @Test
    public fun `authorize continuation drops a ChallengeEmail action without an index`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL_NO_INDEX)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.nextActions, `is`(empty()))
    }

    @Test
    public fun `authorize continuation maps the OTP channel case insensitively`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP_MIXED_CASE_CHANNEL)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        val action = error.nextActions[0] as NextAction.VerifyOtp
        assertThat(action.channel, `is`(OtpChannel.SMS))
    }

    @Test
    public fun `authorize continuation surfaces Unknown next action for unrecognised actions`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_UNKNOWN)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        val action = error.nextActions[0] as NextAction.Unknown
        assertThat(action.rawAction, `is`("action:future:unknown:v1"))
    }

    @Test
    public fun `authorize continuation can carry multiple next actions`() {
        mockAPI.willReturnContinuationWith(
            EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL,
            EmbeddedAuthMockServer.NEXT_IDENTIFY_PHONE,
        )

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.nextActions, hasSize(2))
        assertThat(error.nextActions[0], instanceOf(NextAction.IdentifyEmail::class.java))
        assertThat(error.nextActions[1], instanceOf(NextAction.IdentifyPhone::class.java))
    }

    @Test
    public fun `authorize surfaces access_denied as a terminal error with no next actions`() {
        mockAPI.willReturnAccessDenied()

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.isInsufficientAuthorization, `is`(false))
        assertThat(error.isAccessDenied, `is`(true))
        assertThat(error.nextActions, `is`(empty()))
    }

    @Test
    public fun `authorize surfaces too_many_attempts as a terminal error`() {
        mockAPI.willReturnTooManyAttempts()

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.isTooManyAttempts, `is`(true))
        assertThat(error.statusCode, `is`(429))
    }

    @Test
    public fun `authorize surfaces too_many_logins as a terminal error`() {
        mockAPI.willReturnTooManyLogins()

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.isTooManyLogins, `is`(true))
        assertThat(error.statusCode, `is`(429))
    }

    @Test
    public fun `verifyOtp flags a wrong code as recoverable with retry actions`() {
        establishSession()
        mockAPI.willReturnInvalidCode()

        val error = assertEmbeddedError { client.verifyOtp("000000").execute() }

        assertThat(error.isInvalidCode, `is`(true))
        assertThat(error.isInsufficientAuthorization, `is`(true))
        assertThat(error.isAccessDenied, `is`(false))
        assertThat(error.nextActions, `is`(not(empty())))
    }

    @Test
    public fun `verifyOtp flags too many wrong OTP attempts as terminal`() {
        establishSession()
        mockAPI.willReturnTooManyWrongOtpAttempts()

        val error = assertEmbeddedError { client.verifyOtp("000000").execute() }

        assertThat(error.isTooManyWrongOtpAttempts, `is`(true))
        assertThat(error.isAccessDenied, `is`(true))
        assertThat(error.isInvalidCode, `is`(false))
    }

    @Test
    public fun `verifyOtp flags an expired challenge as terminal`() {
        establishSession()
        mockAPI.willReturnChallengeExpired()

        val error = assertEmbeddedError { client.verifyOtp("000000").execute() }

        assertThat(error.isChallengeExpired, `is`(true))
        assertThat(error.isAccessDenied, `is`(true))
    }

    @Test
    public fun `identify with email continuation sets isInsufficientAuthorization and populates nextActions`() {
        establishSession()
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL)

        val error = assertEmbeddedError { client.identify("jane@example.com", IdentifierType.EMAIL).execute() }

        assertThat(error.isInsufficientAuthorization, `is`(true))
        assertThat(error.nextActions[0], instanceOf(NextAction.ChallengeEmail::class.java))
    }

    @Test
    public fun `identify with email surfaces a terminal error`() {
        establishSession()
        mockAPI.willReturnAccessDenied()

        val error = assertEmbeddedError { client.identify("jane@example.com", IdentifierType.EMAIL).execute() }

        assertThat(error.isAccessDenied, `is`(true))
        assertThat(error.nextActions, `is`(empty()))
    }

    @Test
    public fun `challengeEmail continuation sets isInsufficientAuthorization and populates nextActions`() {
        establishSession()
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP)

        val error = assertEmbeddedError { client.challengeEmail().execute() }

        assertThat(error.isInsufficientAuthorization, `is`(true))
        assertThat(error.nextActions[0], instanceOf(NextAction.VerifyOtp::class.java))
    }

    @Test
    public fun `challengeEmail surfaces a terminal error`() {
        establishSession()
        mockAPI.willReturnTooManyAttempts()

        val error = assertEmbeddedError { client.challengeEmail().execute() }

        assertThat(error.isTooManyAttempts, `is`(true))
    }

    @Test
    public fun `verifyOtp surfaces a continuation when the server requires further steps`() {
        establishSession()
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP)

        val error = assertEmbeddedError { client.verifyOtp("123456").execute() }

        assertThat(error.isInsufficientAuthorization, `is`(true))
        assertThat(error.nextActions[0], instanceOf(NextAction.VerifyOtp::class.java))
    }

    @Test
    public fun `verifyOtp surfaces a terminal error`() {
        establishSession()
        mockAPI.willReturnTooManyAttempts()

        val error = assertEmbeddedError { client.verifyOtp("123456").execute() }

        assertThat(error.isTooManyAttempts, `is`(true))
    }



    @Test
    public fun `the auth_session is rotated between steps`() {
        // authorize → session A; identify → should send A, server returns B; challengeEmail → should send B
        mockAPI.willReturnInsufficientAuthorization(EmbeddedAuthMockServer.AUTH_SESSION)
        try { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() } catch (_: EmbeddedAuthException) {}
        mockAPI.takeRequest()

        mockAPI.willReturnInsufficientAuthorization(EmbeddedAuthMockServer.ROTATED_AUTH_SESSION)
        try { client.identify("jane@example.com", IdentifierType.EMAIL).execute() } catch (_: EmbeddedAuthException) {}
        assertThat(bodyOf(mockAPI.takeRequest()).getString("auth_session"), `is`(EmbeddedAuthMockServer.AUTH_SESSION))

        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()
        client.verifyOtp("123456").execute()
        assertThat(bodyOf(mockAPI.takeRequest()).getString("auth_session"), `is`(EmbeddedAuthMockServer.ROTATED_AUTH_SESSION))
    }

    @Test
    public fun `the session is cleared after a successful token exchange`() {
        establishSession()
        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()
        client.verifyOtp("123456").execute()
        mockAPI.takeRequest()
        mockAPI.takeRequest()

        // Session is gone — any follow-on step must fail with no_active_session.
        val error = assertEmbeddedError { client.verifyOtp("999999").execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    @Test
    public fun `a failed token exchange leaves the session intact for retry`() {
        establishSession()
        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokensWithoutIdToken()
        try { client.verifyOtp("123456").execute() } catch (_: EmbeddedAuthException) {}
        mockAPI.takeRequest()
        mockAPI.takeRequest()

        // Session still active — verifyOtp should reach the server rather than failing immediately.
        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()
        val credentials = client.verifyOtp("123456").execute()
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))
    }

    @Test
    public fun `calling authorize again resets an in-progress flow`() {
        establishSession()

        // Start a fresh flow — the old session must not bleed into the next step.
        mockAPI.willReturnInsufficientAuthorization(EmbeddedAuthMockServer.ROTATED_AUTH_SESSION)
        try { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() } catch (_: EmbeddedAuthException) {}
        mockAPI.takeRequest()

        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()
        client.verifyOtp("123456").execute()
        assertThat(
            bodyOf(mockAPI.takeRequest()).getString("auth_session"),
            `is`(EmbeddedAuthMockServer.ROTATED_AUTH_SESSION)
        )
    }

    @Test
    public fun `a transient server error leaves the session intact for retry`() {
        establishSession()

        // A 5xx is not terminal — the session must survive so the same step can be retried.
        mockAPI.willReturnPlainTextError()
        assertEmbeddedError { client.challengeEmail().execute() }
        mockAPI.takeRequest()

        // The retry must still carry the established session, not fail with no_active_session.
        mockAPI.willReturnInsufficientAuthorization(EmbeddedAuthMockServer.ROTATED_AUTH_SESSION)
        assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(
            bodyOf(mockAPI.takeRequest()).getString("auth_session"),
            `is`(EmbeddedAuthMockServer.AUTH_SESSION)
        )
    }

    @Test
    public fun `a network error leaves the session intact for retry`() {
        establishSession()
        mockAPI.shutdown()

        // The step fails at the network layer — transient, so the session must survive.
        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.isNetworkError, `is`(true))

        // A preserved session means the retry reaches the network again (another network error);
        // a wrongly-cleared session would instead short-circuit client-side with no_active_session.
        val retry = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(retry.isNetworkError, `is`(true))
        assertThat(retry.code, not(`is`("no_active_session")))
    }

    @Test
    public fun `a terminal access_denied clears the session`() {
        establishSession()

        mockAPI.willReturnAccessDenied()
        assertEmbeddedError { client.challengeEmail().execute() }
        mockAPI.takeRequest()

        // Terminal failure ended the flow — any follow-on step must fail with no_active_session.
        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    @Test
    public fun `a terminal rate-limit error clears the session`() {
        establishSession()

        mockAPI.willReturnTooManyAttempts()
        assertEmbeddedError { client.challengeEmail().execute() }
        mockAPI.takeRequest()

        // Rate limiting is terminal for this flow — the session must be dropped.
        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.code, `is`("no_active_session"))
    }



    // --- await() (coroutine) coverage: the step wrappers run distinct code paths for await() ---

    @Test
    public fun `authorize await surfaces a continuation through the coroutine path`(): Unit = runTest {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL)

        val error = assertEmbeddedErrorSuspending {
            client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).await()
        }

        assertThat(error.isInsufficientAuthorization, `is`(true))
        assertThat(error.nextActions[0], instanceOf(NextAction.IdentifyEmail::class.java))
    }

    @Test
    public fun `identify with email await POSTs the correct action and surfaces a continuation`(): Unit = runTest {
        establishSession()
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL)

        val error = assertEmbeddedErrorSuspending { client.identify("jane@example.com", IdentifierType.EMAIL).await() }

        assertThat(error.nextActions[0], instanceOf(NextAction.ChallengeEmail::class.java))
        val body = bodyOf(mockAPI.takeRequest())
        assertThat(body.getString("action"), `is`("action:identify:email:v1"))
        assertThat(body.getString("email"), `is`("jane@example.com"))
    }

    @Test
    public fun `challengeEmail await surfaces a terminal error and clears the session`(): Unit = runTest {
        establishSession()
        mockAPI.willReturnAccessDenied()

        val error = assertEmbeddedErrorSuspending { client.challengeEmail().await() }
        assertThat(error.isAccessDenied, `is`(true))
        mockAPI.takeRequest()

        // onStepFailure ran on the coroutine path — the session must be gone.
        val followOn = assertEmbeddedErrorSuspending { client.challengeEmail().await() }
        assertThat(followOn.code, `is`("no_active_session"))
    }

    @Test
    public fun `verifyOtp await exchanges the code and returns credentials`(): Unit = runTest {
        establishSession()
        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()

        val credentials = client.verifyOtp("123456", OtpType.OOB).await()

        assertThat(credentials.idToken, `is`(EmbeddedAuthMockServer.ID_TOKEN))
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))

        // onFlowComplete ran on the coroutine path — the session must be cleared.
        val followOn = assertEmbeddedErrorSuspending { client.verifyOtp("999999").await() }
        assertThat(followOn.code, `is`("no_active_session"))
    }

    @Test
    public fun `verifyOtp await leaves the session intact when the token exchange fails`(): Unit = runTest {
        establishSession()
        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokensWithoutIdToken()

        assertEmbeddedErrorSuspending { client.verifyOtp("123456").await() }
        mockAPI.takeRequest()
        mockAPI.takeRequest()

        // The failed exchange must not clear the session — a retry should reach the server.
        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()
        val credentials = client.verifyOtp("123456").await()
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))
    }



    /** Enqueues a continuation and calls authorize to populate [transactionState]. */
    private fun establishSession() {
        mockAPI.willReturnInsufficientAuthorization()
        try { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() } catch (_: EmbeddedAuthException) {}
        mockAPI.takeRequest()
    }

    private fun assertEmbeddedError(block: () -> Unit): EmbeddedAuthException {
        var error: EmbeddedAuthException? = null
        try { block() } catch (ex: EmbeddedAuthException) { error = ex }
        assertThat("expected EmbeddedAuthException", error, `is`(notNullValue()))
        return error!!
    }

    private suspend fun assertEmbeddedErrorSuspending(block: suspend () -> Unit): EmbeddedAuthException {
        var error: EmbeddedAuthException? = null
        try { block() } catch (ex: EmbeddedAuthException) { error = ex }
        assertThat("expected EmbeddedAuthException", error, `is`(notNullValue()))
        return error!!
    }


    private fun bodyOf(request: RecordedRequest): JSONObject =
        JSONObject(request.body.readUtf8())

    private companion object {
        private const val CLIENT_ID = "CLIENT_ID"
    }
}
