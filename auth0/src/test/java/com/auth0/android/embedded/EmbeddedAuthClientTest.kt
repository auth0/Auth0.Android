package com.auth0.android.embedded

import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.embedded.authorize.IdentifierType
import com.auth0.android.embedded.authorize.NextAction
import com.auth0.android.embedded.authorize.OtpChannel
import com.auth0.android.embedded.authorize.OtpType
import com.auth0.android.embedded.authorize.embeddedAuthErrorAdapter
import com.auth0.android.util.EmbeddedAuthMockServer
import com.auth0.android.util.SSLTestUtils.testClient
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.empty
import org.hamcrest.Matchers.not
import org.hamcrest.Matchers.hasSize
import org.hamcrest.Matchers.instanceOf
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.notNullValue
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.StringReader

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

    // ── Authorize — request shape ───────────────────────────────────────────────

    @Test
    public fun `authorize should POST the authorize endpoint with the default scope and no audience`() {
        mockAPI.willReturnJsonError()

        try {
            client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute()
        } catch (_: EmbeddedAuthException) {
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

    // ── verifyOtp — token exchange ──────────────────────────────────────────────

    @Test
    public fun `verifyOtp should exchange the code and return credentials with an id token`() {
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

        val error = assertEmbeddedError { client.verifyOtp("123456", OtpType.OOB).execute() }

        assertThat(error, `is`(notNullValue()))
    }

    // ── identify ────────────────────────────────────────────────────────────────

    @Test
    public fun `identify with email should fail with no_active_session when no flow is in progress`() {
        val error = assertEmbeddedError { client.identify("jane@example.com", IdentifierType.EMAIL).execute() }
        assertThat(error.code, `is`("no_active_session"))
        assertThat(error.error, `is`(EmbeddedAuthError.NoActiveSession))
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

    // ── challengeEmail ───────────────────────────────────────────────────────────

    @Test
    public fun `challengeEmail should fail with no_active_session when no flow is in progress`() {
        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.code, `is`("no_active_session"))
        assertThat(error.error, `is`(EmbeddedAuthError.NoActiveSession))
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

    // ── verifyOtp — no session ───────────────────────────────────────────────────

    @Test
    public fun `verifyOtp should fail with no_active_session when no flow is in progress`() {
        val error = assertEmbeddedError { client.verifyOtp("123456").execute() }
        assertThat(error.code, `is`("no_active_session"))
        assertThat(error.error, `is`(EmbeddedAuthError.NoActiveSession))
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

    // ── Continuation / typed-error mapping ──────────────────────────────────────

    @Test
    public fun `authorize continuation surfaces InsufficientAuthorization and populates nextActions`() {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL)

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.error, instanceOf(EmbeddedAuthError.InsufficientAuthorization::class.java))
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
    public fun `authorize surfaces AccessDenied as a terminal error with no next actions`() {
        mockAPI.willReturnAccessDenied()

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.AccessDenied))
    }

    @Test
    public fun `authorize surfaces TooManyAttempts as a terminal error`() {
        mockAPI.willReturnTooManyAttempts()

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.TooManyAttempts))
        assertThat(error.statusCode, `is`(429))
    }

    @Test
    public fun `authorize surfaces TooManyLogins as a terminal error`() {
        mockAPI.willReturnTooManyLogins()

        val error = assertEmbeddedError { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.TooManyLogins))
        assertThat(error.statusCode, `is`(429))
    }

    @Test
    public fun `verifyOtp flags a wrong code as recoverable with retry actions`() {
        establishSession()
        mockAPI.willReturnInvalidCode()

        val error = assertEmbeddedError { client.verifyOtp("000000").execute() }

        assertThat(error.error, instanceOf(EmbeddedAuthError.InsufficientAuthorization::class.java))
        assertThat(error.nextActions, `is`(not(empty())))
    }

    @Test
    public fun `verifyOtp flags too many wrong OTP attempts as TooManyWrongOtpAttempts`() {
        establishSession()
        mockAPI.willReturnTooManyWrongOtpAttempts()

        val error = assertEmbeddedError { client.verifyOtp("000000").execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.TooManyWrongOtpAttempts))
    }

    @Test
    public fun `verifyOtp flags an expired challenge as ChallengeExpired`() {
        establishSession()
        mockAPI.willReturnChallengeExpired()

        val error = assertEmbeddedError { client.verifyOtp("000000").execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.ChallengeExpired))
    }

    @Test
    public fun `authorize surfaces SessionExpired when the continuation returns invalid_grant`() {
        mockAPI.willReturnInsufficientAuthorization()
        try { client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).execute() } catch (_: EmbeddedAuthException) {}
        mockAPI.takeRequest()

        mockAPI.willReturnInvalidGrant()

        val error = assertEmbeddedError { client.challengeEmail().execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.SessionExpired))
        assertThat(error.code, `is`("invalid_grant"))
    }

    @Test
    public fun `identify with email continuation surfaces InsufficientAuthorization and populates nextActions`() {
        establishSession()
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_CHALLENGE_EMAIL)

        val error = assertEmbeddedError { client.identify("jane@example.com", IdentifierType.EMAIL).execute() }

        assertThat(error.error, instanceOf(EmbeddedAuthError.InsufficientAuthorization::class.java))
        assertThat(error.nextActions[0], instanceOf(NextAction.ChallengeEmail::class.java))
    }

    @Test
    public fun `identify with email surfaces a terminal error`() {
        establishSession()
        mockAPI.willReturnAccessDenied()

        val error = assertEmbeddedError { client.identify("jane@example.com", IdentifierType.EMAIL).execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.AccessDenied))
    }

    @Test
    public fun `challengeEmail continuation surfaces InsufficientAuthorization and populates nextActions`() {
        establishSession()
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP)

        val error = assertEmbeddedError { client.challengeEmail().execute() }

        assertThat(error.error, instanceOf(EmbeddedAuthError.InsufficientAuthorization::class.java))
        assertThat(error.nextActions[0], instanceOf(NextAction.VerifyOtp::class.java))
    }

    @Test
    public fun `challengeEmail surfaces a terminal error`() {
        establishSession()
        mockAPI.willReturnTooManyAttempts()

        val error = assertEmbeddedError { client.challengeEmail().execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.TooManyAttempts))
    }

    @Test
    public fun `verifyOtp surfaces a continuation when the server requires further steps`() {
        establishSession()
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_VERIFY_OTP)

        val error = assertEmbeddedError { client.verifyOtp("123456").execute() }

        assertThat(error.error, instanceOf(EmbeddedAuthError.InsufficientAuthorization::class.java))
        assertThat(error.nextActions[0], instanceOf(NextAction.VerifyOtp::class.java))
    }

    @Test
    public fun `verifyOtp surfaces a terminal error`() {
        establishSession()
        mockAPI.willReturnTooManyAttempts()

        val error = assertEmbeddedError { client.verifyOtp("123456").execute() }

        assertThat(error.error, `is`(EmbeddedAuthError.TooManyAttempts))
    }

    // ── Session-management behaviour ─────────────────────────────────────────────

    @Test
    public fun `the auth_session is rotated between steps`() {
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

        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()
        val credentials = client.verifyOtp("123456").execute()
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))
    }

    @Test
    public fun `calling authorize again resets an in-progress flow`() {
        establishSession()

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
    public fun `a 5xx server error leaves the session intact for retry`() {
        establishSession()

        mockAPI.willReturnPlainTextError()
        assertEmbeddedError { client.challengeEmail().execute() }
        mockAPI.takeRequest()

        mockAPI.willReturnPlainTextError()
        val retry = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(retry.code, not(`is`("no_active_session")))
    }

    @Test
    public fun `a network error leaves the session intact for retry`() {
        establishSession()
        mockAPI.shutdown()

        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.error, `is`(EmbeddedAuthError.Network))

        val retry = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(retry.error, `is`(EmbeddedAuthError.Network))
        assertThat(retry.code, not(`is`("no_active_session")))
    }

    @Test
    public fun `a terminal access_denied clears the session`() {
        establishSession()

        mockAPI.willReturnAccessDenied()
        assertEmbeddedError { client.challengeEmail().execute() }
        mockAPI.takeRequest()

        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    @Test
    public fun `a terminal rate-limit error clears the session`() {
        establishSession()

        mockAPI.willReturnTooManyAttempts()
        assertEmbeddedError { client.challengeEmail().execute() }
        mockAPI.takeRequest()

        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    @Test
    public fun `a SessionExpired error clears the session`() {
        establishSession()

        mockAPI.willReturnInvalidGrant()
        assertEmbeddedError { client.challengeEmail().execute() }
        mockAPI.takeRequest()

        val error = assertEmbeddedError { client.challengeEmail().execute() }
        assertThat(error.code, `is`("no_active_session"))
    }

    // ── await() (coroutine) paths ──────────────────────────────────────────────

    @Test
    public fun `authorize await surfaces a continuation through the coroutine path`(): Unit = runTest {
        mockAPI.willReturnContinuationWith(EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL)

        val error = assertEmbeddedErrorSuspending {
            client.authorize(EmbeddedAuthMockServer.AUTHORIZE_CONNECTION).await()
        }

        assertThat(error.error, instanceOf(EmbeddedAuthError.InsufficientAuthorization::class.java))
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
        assertThat(error.error, `is`(EmbeddedAuthError.AccessDenied))
        mockAPI.takeRequest()

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

        mockAPI.willReturnAuthorizeCode()
        mockAPI.willReturnTokens()
        val credentials = client.verifyOtp("123456").await()
        assertThat(credentials.accessToken, `is`(EmbeddedAuthMockServer.ACCESS_TOKEN))
    }

    // ── Adapter mapping unit tests (§5 of EmbeddedAuthError spec) ─────────────

    @Test
    public fun `adapter maps insufficient_authorization to InsufficientAuthorization`() {
        val json = """{"error":"insufficient_authorization","error_description":"continue","auth_session":"s","next":[${EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL}]}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(403, StringReader(json))
        val error = ex.error as EmbeddedAuthError.InsufficientAuthorization
        assertThat(error.nextActions, hasSize(1))
        assertThat(error.nextActions[0], instanceOf(NextAction.IdentifyEmail::class.java))
        assertThat(error.reason, `is`(EmbeddedAuthError.InsufficientAuthorization.Reason.NONE))
    }

    @Test
    public fun `adapter maps insufficient_authorization + invalid_code to reason INVALID_CODE`() {
        val json = """{"error":"insufficient_authorization","error_description":"invalid_code","auth_session":"s","next":[${EmbeddedAuthMockServer.NEXT_VERIFY_OTP}]}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(403, StringReader(json))
        val error = ex.error as EmbeddedAuthError.InsufficientAuthorization
        assertThat(error.reason, `is`(EmbeddedAuthError.InsufficientAuthorization.Reason.INVALID_CODE))
    }

    @Test
    public fun `adapter maps insufficient_authorization + invalid_identifier_or_code to reason INVALID_IDENTIFIER_OR_CODE`() {
        val json = """{"error":"insufficient_authorization","error_description":"invalid_identifier_or_code","auth_session":"s","next":[${EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL}]}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(403, StringReader(json))
        val error = ex.error as EmbeddedAuthError.InsufficientAuthorization
        assertThat(error.reason, `is`(EmbeddedAuthError.InsufficientAuthorization.Reason.INVALID_IDENTIFIER_OR_CODE))
    }

    @Test
    public fun `adapter maps insufficient_authorization without a known description to reason NONE`() {
        val json = """{"error":"insufficient_authorization","auth_session":"s","next":[${EmbeddedAuthMockServer.NEXT_IDENTIFY_EMAIL}]}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(403, StringReader(json))
        val error = ex.error as EmbeddedAuthError.InsufficientAuthorization
        assertThat(error.reason, `is`(EmbeddedAuthError.InsufficientAuthorization.Reason.NONE))
    }

    @Test
    public fun `adapter maps access_denied + too_many_wrong_otp_attempts to TooManyWrongOtpAttempts`() {
        val json = """{"error":"access_denied","error_description":"too_many_wrong_otp_attempts"}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(403, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.TooManyWrongOtpAttempts))
    }

    @Test
    public fun `adapter maps access_denied + challenge_expired to ChallengeExpired`() {
        val json = """{"error":"access_denied","error_description":"challenge_expired"}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(403, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.ChallengeExpired))
    }

    @Test
    public fun `adapter maps access_denied with any other description to AccessDenied`() {
        val json = """{"error":"access_denied","error_description":"Access denied."}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(403, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.AccessDenied))
    }

    @Test
    public fun `adapter maps 429 too_many_requests + too_many_attempts to TooManyAttempts`() {
        val json = """{"error":"too_many_requests","error_description":"too_many_attempts"}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(429, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.TooManyAttempts))
    }

    @Test
    public fun `adapter maps 429 too_many_requests + too_many_logins to TooManyLogins`() {
        val json = """{"error":"too_many_requests","error_description":"too_many_logins"}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(429, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.TooManyLogins))
    }

    @Test
    public fun `adapter maps invalid_grant to SessionExpired`() {
        val json = """{"error":"invalid_grant","error_description":"The auth_session has expired."}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(400, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.SessionExpired))
    }

    @Test
    public fun `adapter maps invalid_request to InvalidRequest`() {
        val json = """{"error":"invalid_request","error_description":"Bad request."}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(400, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.InvalidRequest))
    }

    @Test
    public fun `adapter maps server_error to Unknown`() {
        val json = """{"error":"server_error","error_description":"Unexpected error."}"""
        val ex = embeddedAuthErrorAdapter().fromJsonResponse(500, StringReader(json))
        assertThat(ex.error, `is`(EmbeddedAuthError.Unknown))
    }

    @Test
    public fun `adapter maps blank body to Unknown`() {
        val ex = embeddedAuthErrorAdapter().fromRawResponse(404, "", emptyMap())
        assertThat(ex.error, `is`(EmbeddedAuthError.Unknown))
        assertThat(ex.code, `is`(Auth0Exception.EMPTY_BODY_ERROR))
    }

    @Test
    public fun `adapter maps non-JSON body to Unknown`() {
        val ex = embeddedAuthErrorAdapter().fromRawResponse(500, "Internal Server Error", emptyMap())
        assertThat(ex.error, `is`(EmbeddedAuthError.Unknown))
        assertThat(ex.code, `is`(Auth0Exception.NON_JSON_ERROR))
    }

    @Test
    public fun `adapter maps network exception to Network`() {
        val ex = embeddedAuthErrorAdapter().fromException(java.net.UnknownHostException("host not found"))
        assertThat(ex.error, `is`(EmbeddedAuthError.Network))
    }

    @Test
    public fun `adapter maps non-network exception to Unknown`() {
        val ex = embeddedAuthErrorAdapter().fromException(RuntimeException("unexpected"))
        assertThat(ex.error, `is`(EmbeddedAuthError.Unknown))
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

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

/** Extracts nextActions from an InsufficientAuthorization error for concise assertions. */
private val EmbeddedAuthException.nextActions: List<NextAction>
    get() = (error as EmbeddedAuthError.InsufficientAuthorization).nextActions
