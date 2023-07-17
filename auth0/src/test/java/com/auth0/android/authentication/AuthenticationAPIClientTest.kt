package com.auth0.android.authentication

import android.content.Context
import android.content.res.Resources
import com.auth0.android.Auth0
import com.auth0.android.authentication.ParameterBuilder.Companion.newBuilder
import com.auth0.android.provider.JwtTestUtils
import com.auth0.android.request.HttpMethod
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ThreadSwitcherShadow
import com.auth0.android.result.*
import com.auth0.android.util.Auth0UserAgent
import com.auth0.android.util.AuthenticationAPIMockServer
import com.auth0.android.util.AuthenticationCallbackMatcher
import com.auth0.android.util.MockAuthenticationCallback
import com.auth0.android.util.SSLTestUtils.testClient
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.nhaarman.mockitokotlin2.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.hamcrest.collection.IsMapContaining
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLooper
import java.io.ByteArrayInputStream
import java.io.FileReader
import java.io.InputStream
import java.security.PublicKey
import java.util.*

@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ThreadSwitcherShadow::class])
public class AuthenticationAPIClientTest {
    private lateinit var client: AuthenticationAPIClient
    private lateinit var gson: Gson
    private lateinit var mockAPI: AuthenticationAPIMockServer

    @Before
    public fun setUp() {
        mockAPI = AuthenticationAPIMockServer()
        val auth0 = auth0
        client = AuthenticationAPIClient(auth0)
        gson = GsonBuilder().serializeNulls().create()
    }

    @After
    public fun tearDown() {
        mockAPI.shutdown()
    }

    @Test
    public fun shouldUseCustomNetworkingClient() {
        val account = Auth0("client-id", "https://tenant.auth0.com/")
        val jsonResponse = FileReader("src/test/resources/credentials_openid.json").readText()
        val inputStream: InputStream = ByteArrayInputStream(jsonResponse.toByteArray())
        val response = ServerResponse(200, inputStream, emptyMap())
        val networkingClient: NetworkingClient = mock()
        whenever(networkingClient.load(any<String>(), any<RequestOptions>()))
            .thenReturn(response)

        account.networkingClient = networkingClient
        val client = AuthenticationAPIClient(account)
        val request = client.login("johndoe", "secret")
        request.execute()

        argumentCaptor<RequestOptions>().apply {
            verify(networkingClient).load(eq("https://tenant.auth0.com/oauth/token"), capture())
            assertThat(firstValue, Matchers.`is`(Matchers.notNullValue()))
            assertThat(
                firstValue.method,
                Matchers.`is`(Matchers.instanceOf(HttpMethod.POST::class.java))
            )
            assertThat(firstValue.parameters, IsMapContaining.hasEntry("username", "johndoe"))
            assertThat(firstValue.parameters, IsMapContaining.hasEntry("password", "secret"))
            assertThat(firstValue.headers, IsMapContaining.hasKey("Auth0-Client"))
        }
    }

    @Test
    public fun shouldSetAuth0UserAgentIfPresent() {
        val auth0UserAgent: Auth0UserAgent = mock()
        whenever(auth0UserAgent.value).thenReturn("the-user-agent-data")
        val factory: RequestFactory<AuthenticationException> = mock()
        val account = Auth0(CLIENT_ID, DOMAIN)
        account.auth0UserAgent = auth0UserAgent
        AuthenticationAPIClient(account, factory, gson)
        verify(factory).setAuth0ClientInfo("the-user-agent-data")
    }

    @Test
    public fun shouldCreateClientWithAccountInfo() {
        val client = AuthenticationAPIClient(Auth0(CLIENT_ID, DOMAIN))
        assertThat(client, Matchers.`is`(Matchers.notNullValue()))
        assertThat(client.clientId, Matchers.equalTo(CLIENT_ID))
        assertThat(client.baseURL.toHttpUrlOrNull()!!, Matchers.notNullValue())
        assertThat(client.baseURL.toHttpUrlOrNull()!!.scheme, Matchers.equalTo("https"))
        assertThat(client.baseURL.toHttpUrlOrNull()!!.host, Matchers.equalTo(DOMAIN))
        assertThat(client.baseURL.toHttpUrlOrNull()!!.pathSize, Matchers.`is`(1))
        assertThat(client.baseURL.toHttpUrlOrNull()!!.encodedPath, Matchers.`is`("/"))
    }

    @Test
    public fun shouldCreateClientWithContextInfo() {
        val context: Context = mock()
        val resources: Resources = mock()
        whenever(context.packageName).thenReturn("com.myapp")
        whenever(context.resources).thenReturn(resources)
        whenever(
            resources.getIdentifier(
                eq("com_auth0_client_id"),
                eq("string"),
                eq("com.myapp")
            )
        ).thenReturn(222)
        whenever(
            resources.getIdentifier(
                eq("com_auth0_domain"),
                eq("string"),
                eq("com.myapp")
            )
        ).thenReturn(333)
        whenever(context.getString(eq(222))).thenReturn(CLIENT_ID)
        whenever(context.getString(eq(333))).thenReturn(DOMAIN)
        val client = AuthenticationAPIClient(Auth0(context))
        assertThat(client, Matchers.`is`(Matchers.notNullValue()))
        assertThat(client.clientId, Matchers.`is`(CLIENT_ID))
        assertThat(client.baseURL, Matchers.equalTo("https://" + DOMAIN + "/"))
    }

    @Test
    public fun shouldLoginWithMFAOTPCode() {
        mockAPI.willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        client.loginWithOTP("ey30.the-mfa-token.value", "123456")
            .start(callback)
        ShadowLooper.idleMainLooper()
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/mfa-otp")
        )
        assertThat(body, Matchers.hasEntry("mfa_token", "ey30.the-mfa-token.value"))
        assertThat(body, Matchers.hasEntry("otp", "123456"))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.not(Matchers.hasKey("password")))
        assertThat(body, Matchers.not(Matchers.hasKey("connection")))
    }

    @Test
    public fun shouldLoginWithMFARecoveryCode() {
        mockAPI.willReturnSuccessfulLoginWithRecoveryCode()
        val callback = MockAuthenticationCallback<Credentials>()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        client.loginWithRecoveryCode("ey30.the-mfa-token.value", "123456")
            .start(callback)
        ShadowLooper.idleMainLooper()
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        assertThat(callback.payload.recoveryCode, Matchers.`is`("654321"))
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/mfa-recovery-code")
        )
        assertThat(body, Matchers.hasEntry("mfa_token", "ey30.the-mfa-token.value"))
        assertThat(body, Matchers.hasEntry("recovery_code", "123456"))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
    }

    @Test
    public fun shouldLoginWithMFAOOBCode() {
        mockAPI.willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        client.loginWithOOB("ey30.the-mfa-token.value", "123456", null)
            .start(callback)
        ShadowLooper.idleMainLooper()
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/mfa-oob")
        )
        assertThat(body, Matchers.hasEntry("mfa_token", "ey30.the-mfa-token.value"))
        assertThat(body, Matchers.hasEntry("oob_code", "123456"))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
        assertThat(body, Matchers.not(Matchers.hasKey("binding_code")))
    }

    @Test
    public fun shouldLoginWithMFAOOBCodeAndBindingCode() {
        mockAPI.willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        client.loginWithOOB("ey30.the-mfa-token.value", "123456", "abcdefg")
            .start(callback)
        ShadowLooper.idleMainLooper()
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/mfa-oob")
        )
        assertThat(body, Matchers.hasEntry("mfa_token", "ey30.the-mfa-token.value"))
        assertThat(body, Matchers.hasEntry("oob_code", "123456"))
        assertThat(body, Matchers.hasEntry("binding_code", "abcdefg"))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
    }

    @Test
    public fun shouldStartMFAChallenge() {
        mockAPI.willReturnSuccessfulMFAChallenge()
        val callback = MockAuthenticationCallback<Challenge>()
        client.multifactorChallenge("ey30.the-mfa-token.value", null, null)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/mfa/challenge"))
        val body = bodyFromRequest<Any>(request)
        assertThat(body, Matchers.hasEntry("mfa_token", "ey30.the-mfa-token.value"))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.not(Matchers.hasKey("challenge_type")))
        assertThat(body, Matchers.not(Matchers.hasKey("authenticator_id")))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Challenge::class.java
            )
        )
    }

    @Test
    public fun shouldStartMFAChallengeWithTypeAndAuthenticator() {
        mockAPI.willReturnSuccessfulMFAChallenge()
        val callback = MockAuthenticationCallback<Challenge>()
        client.multifactorChallenge("ey30.the-mfa-token.value", "oob", "sms|dev_NU1Ofuw3Cw0XCt5x")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/mfa/challenge"))
        val body = bodyFromRequest<Any>(request)
        assertThat(body, Matchers.hasEntry("mfa_token", "ey30.the-mfa-token.value"))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("challenge_type", "oob"))
        assertThat(body, Matchers.hasEntry("authenticator_id", "sms|dev_NU1Ofuw3Cw0XCt5x"))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Challenge::class.java
            )
        )
    }

    @Test
    public fun shouldLoginWithUserAndPasswordSync() {
        val jwt = JwtTestUtils.createTestJWT("HS256", mapOf("sub" to "auth0|123456"))
        mockAPI.willReturnSuccessfulLogin(jwt)
        val credentials = client
            .login(SUPPORT_AUTH0_COM, "voidpassword", MY_CONNECTION)
            .execute()
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        assertThat(credentials.user.getId(), Matchers.`is`("auth0|123456"))
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitLoginWithUserAndPassword(): Unit = runTest {
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client
            .login(SUPPORT_AUTH0_COM, "voidpassword", MY_CONNECTION)
            .await()
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
    }

    @Test
    public fun shouldLoginWithPasswordRealmGrant() {
        mockAPI.willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        client.login(SUPPORT_AUTH0_COM, "some-password", MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", "some-password"))
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(body, Matchers.not(Matchers.hasKey("connection")))
        assertThat(body, Matchers.not(Matchers.hasKey("audience")))
    }

    @Test
    public fun shouldLoginWithUserAndPasswordUsingOAuthTokenEndpoint() {
        mockAPI.willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        client.login(SUPPORT_AUTH0_COM, "some-password")
            .start(callback)
        ShadowLooper.idleMainLooper()
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.`is`("/oauth/token"))
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("grant_type", "password"))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", "some-password"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(body, Matchers.not(Matchers.hasKey("realm")))
        assertThat(body, Matchers.not(Matchers.hasKey("connection")))
        assertThat(body, Matchers.not(Matchers.hasKey("audience")))
    }

    @Test
    public fun shouldLoginWithUserAndPasswordSyncUsingOAuthTokenEndpoint() {
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client
            .login(SUPPORT_AUTH0_COM, "some-password")
            .execute()
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.`is`("/oauth/token"))
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("grant_type", "password"))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", "some-password"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(body, Matchers.not(Matchers.hasKey("realm")))
        assertThat(body, Matchers.not(Matchers.hasKey("connection")))
        assertThat(body, Matchers.not(Matchers.hasKey("audience")))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitLoginWithUserAndPasswordUsingOAuthTokenEndpoint(): Unit = runTest {
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client
            .login(SUPPORT_AUTH0_COM, "some-password")
            .await()
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.`is`("/oauth/token"))
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("grant_type", "password"))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", "some-password"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(body, Matchers.not(Matchers.hasKey("realm")))
        assertThat(body, Matchers.not(Matchers.hasKey("connection")))
        assertThat(body, Matchers.not(Matchers.hasKey("audience")))
    }

    @Test
    public fun shouldFetchUserInfo() {
        mockAPI.willReturnUserInfo()
        val callback = MockAuthenticationCallback<UserProfile>()
        client.userInfo("ACCESS_TOKEN")
            .start(callback)
        ShadowLooper.idleMainLooper()
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                UserProfile::class.java
            )
        )
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(
            request.getHeader("Authorization"),
            Matchers.`is`("Bearer ACCESS_TOKEN")
        )
        assertThat(request.path, Matchers.equalTo("/userinfo"))
    }

    @Test
    public fun shouldFetchUserInfoSync() {
        mockAPI.willReturnUserInfo()
        val profile = client
            .userInfo("ACCESS_TOKEN")
            .execute()
        assertThat(profile, Matchers.`is`(Matchers.notNullValue()))
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(
            request.getHeader("Authorization"),
            Matchers.`is`("Bearer ACCESS_TOKEN")
        )
        assertThat(request.path, Matchers.equalTo("/userinfo"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitFetchUserInfo(): Unit = runTest {
        mockAPI.willReturnUserInfo()
        val profile = client
            .userInfo("ACCESS_TOKEN")
            .await()
        assertThat(profile, Matchers.`is`(Matchers.notNullValue()))
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(
            request.getHeader("Authorization"),
            Matchers.`is`("Bearer ACCESS_TOKEN")
        )
        assertThat(request.path, Matchers.equalTo("/userinfo"))
    }

    @Test
    public fun shouldLoginWithNativeSocialToken() {
        mockAPI.willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        client.loginWithNativeSocialToken("test-token-value", "test-token-type")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE)
        )
        assertThat(body, Matchers.hasEntry("subject_token", "test-token-value"))
        assertThat(body, Matchers.hasEntry("subject_token_type", "test-token-type"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldLoginWithNativeSocialTokenSync() {
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client
            .loginWithNativeSocialToken("test-token-value", "test-token-type")
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE)
        )
        assertThat(body, Matchers.hasEntry("subject_token", "test-token-value"))
        assertThat(body, Matchers.hasEntry("subject_token_type", "test-token-type"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitLoginWithNativeSocialToken(): Unit = runTest {
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client
            .loginWithNativeSocialToken("test-token-value", "test-token-type")
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE)
        )
        assertThat(body, Matchers.hasEntry("subject_token", "test-token-value"))
        assertThat(body, Matchers.hasEntry("subject_token_type", "test-token-type"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldLoginWithPhoneNumberWithCustomConnectionWithOTPGrant() {
        mockAPI.willReturnSuccessfulLogin()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val callback = MockAuthenticationCallback<Credentials>()
        client.loginWithPhoneNumber("+10101010101", "1234", MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("username", "+10101010101"))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldLoginWithPhoneNumberWithOTPGrant() {
        mockAPI.willReturnSuccessfulLogin()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val callback = MockAuthenticationCallback<Credentials>()
        client.loginWithPhoneNumber("+10101010101", "1234")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", "sms"))
        assertThat(body, Matchers.hasEntry("username", "+10101010101"))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldLoginWithPhoneNumberSyncWithOTPGrant() {
        mockAPI.willReturnSuccessfulLogin()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val credentials = client
            .loginWithPhoneNumber("+10101010101", "1234")
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", "sms"))
        assertThat(body, Matchers.hasEntry("username", "+10101010101"))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitLoginWithPhoneNumberWithOTPGrant(): Unit = runTest {
        mockAPI.willReturnSuccessfulLogin()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val credentials = client
            .loginWithPhoneNumber("+10101010101", "1234")
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", "sms"))
        assertThat(body, Matchers.hasEntry("username", "+10101010101"))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldLoginWithEmailOnlyWithCustomConnectionWithOTPGrant() {
        mockAPI.willReturnSuccessfulLogin()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val callback = MockAuthenticationCallback<Credentials>()
        client.loginWithEmail(SUPPORT_AUTH0_COM, "1234", MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldLoginWithEmailOnlyWithOTPGrant() {
        mockAPI.willReturnSuccessfulLogin()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val callback = MockAuthenticationCallback<Credentials>()
        client.loginWithEmail(SUPPORT_AUTH0_COM, "1234")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", "email"))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldLoginWithEmailOnlySyncWithOTPGrant() {
        mockAPI.willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val credentials = client
            .loginWithEmail(SUPPORT_AUTH0_COM, "1234")
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", "email"))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitLoginWithEmailOnlyWithOTPGrant(): Unit = runTest {
        mockAPI.willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        val credentials = client
            .loginWithEmail(SUPPORT_AUTH0_COM, "1234")
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
        )
        assertThat(body, Matchers.hasEntry("realm", "email"))
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("otp", "1234"))
        assertThat(body, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldCreateUserWithUserMetadata() {
        mockAPI.willReturnSuccessfulSignUp()
        val callback = MockAuthenticationCallback<DatabaseUser>()
        val testMetadata = mapOf("country" to "argentina", "age" to "23")
        client.createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION, testMetadata)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<Any>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("user_metadata", testMetadata))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                DatabaseUser::class.java
            )
        )
    }

    @Test
    public fun shouldCreateUserWithUserMetadataSync() {
        mockAPI.willReturnSuccessfulSignUp()
        val testMetadata = mapOf("country" to "argentina", "age" to "23")
        val user = client
            .createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION, testMetadata)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("user_metadata", testMetadata))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitCreateUserWithUserMetadata(): Unit = runTest {
        mockAPI.willReturnSuccessfulSignUp()
        val testMetadata = mapOf("country" to "argentina", "age" to "23")
        val user = client
            .createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION, testMetadata)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("user_metadata", testMetadata))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldCreateUserWithUsername() {
        mockAPI.willReturnSuccessfulSignUp()
        val callback = MockAuthenticationCallback<DatabaseUser>()
        client.createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                DatabaseUser::class.java
            )
        )
    }

    @Test
    public fun shouldCreateUserWithUsernameSync() {
        mockAPI.willReturnSuccessfulSignUp()
        val user = client
            .createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitCreateUserWithUsername(): Unit = runTest {
        mockAPI.willReturnSuccessfulSignUp()
        val user = client
            .createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldCreateUserWithoutUsername() {
        mockAPI.willReturnSuccessfulSignUp()
        val callback = MockAuthenticationCallback<DatabaseUser>()
        client.createUser(email = SUPPORT_AUTH0_COM, PASSWORD, connection = MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                DatabaseUser::class.java
            )
        )
    }

    @Test
    public fun shouldCreateUserWithoutUsernameSync() {
        mockAPI.willReturnSuccessfulSignUp()
        val user = client
            .createUser(email = SUPPORT_AUTH0_COM, PASSWORD, connection = MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitCreateUserWithoutUsername(): Unit = runTest {
        mockAPI.willReturnSuccessfulSignUp()
        val user = client
            .createUser(email = SUPPORT_AUTH0_COM, PASSWORD, connection = MY_CONNECTION)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldNotSendNullUsernameOnSignUp() {
        mockAPI.willReturnSuccessfulSignUp()
        val callback = MockAuthenticationCallback<DatabaseUser>()
        client.createUser(SUPPORT_AUTH0_COM, PASSWORD, null, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                DatabaseUser::class.java
            )
        )
    }

    @Test
    public fun shouldNotSendNullUsernameOnSignUpSync() {
        mockAPI.willReturnSuccessfulSignUp()
        val user = client.createUser(SUPPORT_AUTH0_COM, PASSWORD, null, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitNotSendNullUsernameOnSignUp(): Unit = runTest {
        mockAPI.willReturnSuccessfulSignUp()
        val user = client.createUser(SUPPORT_AUTH0_COM, PASSWORD, null, MY_CONNECTION)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(user, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldLoginWithUsernameSignedUpUserWithPasswordRealmGrant() {
        mockAPI.willReturnSuccessfulSignUp()
            .willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        client.signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val loginRequest = mockAPI.takeRequest()
        assertThat(loginRequest.path, Matchers.equalTo("/oauth/token"))
        val loginBody = bodyFromRequest<String>(loginRequest)
        assertThat(loginBody, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(loginBody, Matchers.hasEntry("password", PASSWORD))
        assertThat(loginBody, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(loginBody, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(loginBody, Matchers.not(Matchers.hasKey("connection")))
    }

    @Test
    public fun shouldSignUpUserWithCustomFields() {
        mockAPI.willReturnSuccessfulSignUp()
            .willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        val custom = newBuilder()
            .set("first_name", FIRST_NAME)
            .set("last_name", LAST_NAME)
            .set("company", COMPANY)
            .asDictionary()
        client.signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
            .addSignUpParameters(custom)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("first_name", FIRST_NAME))
        assertThat(body, Matchers.hasEntry("last_name", LAST_NAME))
        assertThat(body, Matchers.hasEntry("company", COMPANY))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldSignUpUserWithUserMetadata() {
        mockAPI.willReturnSuccessfulSignUp()
            .willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val testMetadata = mapOf("country" to "argentina", "age" to "23")
        val credentials = client
            .signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION, testMetadata)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("user_metadata", testMetadata))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        val loginRequest = mockAPI.takeRequest()
        assertThat(loginRequest.path, Matchers.equalTo("/oauth/token"))
        val loginBody = bodyFromRequest<String>(loginRequest)
        assertThat(loginBody, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(loginBody, Matchers.hasEntry("password", PASSWORD))
        assertThat(loginBody, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(loginBody, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            loginBody,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        assertThat(loginBody, Matchers.hasEntry("client_id", CLIENT_ID))
    }

    @Test
    public fun shouldSignUpUserSync() {
        mockAPI.willReturnSuccessfulSignUp()
            .willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val credentials = client
            .signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        val loginRequest = mockAPI.takeRequest()
        assertThat(loginRequest.path, Matchers.equalTo("/oauth/token"))
        val loginBody = bodyFromRequest<String>(loginRequest)
        assertThat(loginBody, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(loginBody, Matchers.hasEntry("password", PASSWORD))
        assertThat(loginBody, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(loginBody, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            loginBody,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        assertThat(loginBody, Matchers.hasEntry("client_id", CLIENT_ID))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitSignUpUser(): Unit = runTest {

        mockAPI.willReturnSuccessfulSignUp()
            .willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val credentials = client
            .signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("username", SUPPORT))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
        val loginRequest = mockAPI.takeRequest()
        assertThat(loginRequest.path, Matchers.equalTo("/oauth/token"))
        val loginBody = bodyFromRequest<String>(loginRequest)
        assertThat(loginBody, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(loginBody, Matchers.hasEntry("password", PASSWORD))
        assertThat(loginBody, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(loginBody, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            loginBody,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        assertThat(loginBody, Matchers.hasEntry("client_id", CLIENT_ID))
    }

    @Test
    public fun shouldSignUpUserWithoutUsername() {
        mockAPI.willReturnSuccessfulSignUp()
            .willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val callback = MockAuthenticationCallback<Credentials>()
        client.signUp(email = SUPPORT_AUTH0_COM, password = PASSWORD, connection = MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val loginRequest = mockAPI.takeRequest()
        assertThat(loginRequest.path, Matchers.equalTo("/oauth/token"))
        val loginBody = bodyFromRequest<String>(loginRequest)
        assertThat(loginBody, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(loginBody, Matchers.hasEntry("password", PASSWORD))
        assertThat(loginBody, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(loginBody, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(
            loginBody,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        assertThat(loginBody, Matchers.hasEntry("client_id", CLIENT_ID))
    }

    @Test
    public fun shouldLoginSignedUpUserWithPasswordRealmGrant() {
        mockAPI.willReturnSuccessfulSignUp()
            .willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val callback = MockAuthenticationCallback<Credentials>()
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        client.signUp(email = SUPPORT_AUTH0_COM, password = PASSWORD, connection = MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/signup"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("password", PASSWORD))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
        val loginRequest = mockAPI.takeRequest()
        assertThat(loginRequest.path, Matchers.equalTo("/oauth/token"))
        val loginBody = bodyFromRequest<String>(loginRequest)
        assertThat(loginBody, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(loginBody, Matchers.hasEntry("password", PASSWORD))
        assertThat(loginBody, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(loginBody, Matchers.hasEntry("scope", "openid profile email"))
        assertThat(loginBody, Matchers.not(Matchers.hasKey("connection")))
    }

    @Test
    public fun shouldChangePassword() {
        mockAPI.willReturnSuccessfulChangePassword()
        val callback = MockAuthenticationCallback<Void>()
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/change_password"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldChangePasswordSync() {
        mockAPI.willReturnSuccessfulChangePassword()
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/change_password"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitChangePassword(): Unit = runTest {
        mockAPI.willReturnSuccessfulChangePassword()
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/change_password"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
    }

    @Test
    public fun shouldRequestChangePassword() {
        mockAPI.willReturnSuccessfulChangePassword()
        val callback = MockAuthenticationCallback<Void>()
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/change_password"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.not(Matchers.hasKey("password")))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldRequestChangePasswordSync() {
        mockAPI.willReturnSuccessfulChangePassword()
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/change_password"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.not(Matchers.hasKey("password")))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitRequestChangePassword(): Unit = runTest {
        mockAPI.willReturnSuccessfulChangePassword()
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/dbconnections/change_password"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.not(Matchers.hasKey("username")))
        assertThat(body, Matchers.not(Matchers.hasKey("password")))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
    }

    @Test
    public fun shouldSendEmailCodeWithCustomConnection() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.CODE, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendEmailCode() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.CODE)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendEmailCodeSync() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.CODE)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitSendEmailCode(): Unit = runTest {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.CODE)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
    }

    @Test
    public fun shouldSendEmailLink() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.WEB_LINK)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendEmailLinkWithCustomConnection() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.WEB_LINK, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendEmailLinkSync() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.WEB_LINK)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitSendEmailLink(): Unit = runTest {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.WEB_LINK)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
    }

    @Test
    public fun shouldSendEmailLinkAndroidWithCustomConnection() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithEmail(
            SUPPORT_AUTH0_COM,
            PasswordlessType.ANDROID_LINK,
            MY_CONNECTION
        )
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendEmailLinkAndroid() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.ANDROID_LINK)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendEmailLinkAndroidSync() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.ANDROID_LINK)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitSendEmailLinkAndroid(): Unit = runTest {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.ANDROID_LINK)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("email", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", "email"))
    }

    @Test
    public fun shouldSendSMSCodeWithCustomConnection() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.CODE, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendSMSCode() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.CODE)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendSMSCodeSync() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.CODE)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitSendSMSCode(): Unit = runTest {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.CODE)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "code"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
    }

    @Test
    public fun shouldSendSMSLinkWithCustomConnection() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.WEB_LINK, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendSMSLink() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.WEB_LINK)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendSMSLinkSync() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.WEB_LINK)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitSendSMSLink(): Unit = runTest {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.WEB_LINK)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
    }

    @Test
    public fun shouldSendSMSLinkAndroidWithCustomConnection() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.ANDROID_LINK, MY_CONNECTION)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", MY_CONNECTION))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendSMSLinkAndroid() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        val callback = MockAuthenticationCallback<Void>()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.ANDROID_LINK)
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldSendSMSLinkAndroidSync() {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.ANDROID_LINK)
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitSendSMSLinkAndroid(): Unit = runTest {
        mockAPI.willReturnSuccessfulPasswordlessStart()
        client.passwordlessWithSMS("+1123123123", PasswordlessType.ANDROID_LINK)
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/passwordless/start"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("phone_number", "+1123123123"))
        assertThat(body, Matchers.hasEntry("send", "link_android"))
        assertThat(body, Matchers.hasEntry("connection", "sms"))
    }

    @Test
    public fun shouldFetchJsonWebKeys() {
        mockAPI.willReturnEmptyJsonWebKeys()
        val callback = MockAuthenticationCallback<Map<String, PublicKey>>()
        client.fetchJsonWebKeys()
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/.well-known/jwks.json"))
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(callback, AuthenticationCallbackMatcher.hasPayload(emptyMap()))
    }

    @Test
    public fun shouldFetchJsonWebKeysSync() {
        mockAPI.willReturnEmptyJsonWebKeys()
        val result = client.fetchJsonWebKeys()
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/.well-known/jwks.json"))
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(result, Matchers.`is`(Matchers.notNullValue()))
        assertThat(result, Matchers.`is`(emptyMap()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitFetchJsonWebKeys(): Unit = runTest {
        mockAPI.willReturnEmptyJsonWebKeys()
        val result = client.fetchJsonWebKeys()
            .await()
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/.well-known/jwks.json"))
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(result, Matchers.`is`(Matchers.notNullValue()))
        assertThat(result, Matchers.`is`(emptyMap()))
    }

    @Test
    public fun shouldFetchProfileAfterLoginRequest() {
        mockAPI.willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val callback = MockAuthenticationCallback<Authentication>()
        client.getProfileAfter(client.login(SUPPORT_AUTH0_COM, "voidpassword", MY_CONNECTION))
            .start(callback)
        ShadowLooper.idleMainLooper()
        val firstRequest = mockAPI.takeRequest()
        assertThat(firstRequest.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(firstRequest)
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", "voidpassword"))
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        val secondRequest = mockAPI.takeRequest()
        assertThat(
            secondRequest.getHeader("Authorization"),
            Matchers.`is`("Bearer " + AuthenticationAPIMockServer.ACCESS_TOKEN)
        )
        assertThat(secondRequest.path, Matchers.equalTo("/userinfo"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Authentication::class.java
            )
        )
    }

    @Test
    public fun shouldRevokeToken() {
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        mockAPI.willReturnSuccessfulEmptyBody()
        val callback = MockAuthenticationCallback<Void>()
        client.revokeToken("refreshToken")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/revoke"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("token", "refreshToken"))
        assertThat(callback, AuthenticationCallbackMatcher.hasNoError())
    }

    @Test
    public fun shouldRevokeTokenSync() {
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        mockAPI.willReturnSuccessfulEmptyBody()
        client.revokeToken("refreshToken")
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/revoke"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("token", "refreshToken"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitRevokeToken(): Unit = runTest {
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        mockAPI.willReturnSuccessfulEmptyBody()
        client.revokeToken("refreshToken")
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/revoke"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("token", "refreshToken"))
    }

    @Test
    public fun shouldRenewAuthWithOAuthToken() {
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        mockAPI.willReturnSuccessfulLogin()
        val callback = MockAuthenticationCallback<Credentials>()
        client.renewAuth("refreshToken")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("refresh_token", "refreshToken"))
        assertThat(body, Matchers.hasEntry("grant_type", "refresh_token"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldRenewAuthWithOAuthTokenSync() {
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client.renewAuth("refreshToken")
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("refresh_token", "refreshToken"))
        assertThat(body, Matchers.hasEntry("grant_type", "refresh_token"))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitRenewAuthWithOAuthToken(): Unit = runTest {
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client.renewAuth("refreshToken")
            .await()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("refresh_token", "refreshToken"))
        assertThat(body, Matchers.hasEntry("grant_type", "refresh_token"))
        assertThat(body, Matchers.not(Matchers.hasKey("scope")))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldRenewAuthWithOAuthTokenAndCustomScope() {
        val auth0 = auth0
        val client = AuthenticationAPIClient(auth0)
        mockAPI.willReturnSuccessfulLogin()
        val credentials = client.renewAuth("refreshToken")
            .addParameter("scope", "read:users")
            .execute()
        val request = mockAPI.takeRequest()
        assertThat(
            request.getHeader("Accept-Language"), Matchers.`is`(
                defaultLocale
            )
        )
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("refresh_token", "refreshToken"))
        assertThat(body, Matchers.hasEntry("grant_type", "refresh_token"))
        assertThat(body, Matchers.hasEntry("scope", "read:users openid"))
        assertThat(credentials, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldFetchProfileSyncAfterLoginRequest() {
        mockAPI.willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val authentication = client.getProfileAfter(
            client.login(
                SUPPORT_AUTH0_COM,
                "voidpassword",
                MY_CONNECTION
            )
        )
            .execute()
        val firstRequest = mockAPI.takeRequest()
        assertThat(firstRequest.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(firstRequest)
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", "voidpassword"))
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        val secondRequest = mockAPI.takeRequest()
        assertThat(
            secondRequest.getHeader("Authorization"),
            Matchers.`is`("Bearer " + AuthenticationAPIMockServer.ACCESS_TOKEN)
        )
        assertThat(secondRequest.path, Matchers.equalTo("/userinfo"))
        assertThat(authentication, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitFetchProfileAfterLoginRequest(): Unit = runTest {
        mockAPI.willReturnSuccessfulLogin()
            .willReturnUserInfo()
        val authentication = client.getProfileAfter(
            client.login(
                SUPPORT_AUTH0_COM,
                "voidpassword",
                MY_CONNECTION
            )
        )
            .await()
        val firstRequest = mockAPI.takeRequest()
        assertThat(firstRequest.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(firstRequest)
        assertThat(body, Matchers.hasEntry("username", SUPPORT_AUTH0_COM))
        assertThat(body, Matchers.hasEntry("password", "voidpassword"))
        assertThat(body, Matchers.hasEntry("realm", MY_CONNECTION))
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(
            body,
            Matchers.hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
        )
        val secondRequest = mockAPI.takeRequest()
        assertThat(
            secondRequest.getHeader("Authorization"),
            Matchers.`is`("Bearer " + AuthenticationAPIMockServer.ACCESS_TOKEN)
        )
        assertThat(secondRequest.path, Matchers.equalTo("/userinfo"))
        assertThat(authentication, Matchers.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldGetOAuthTokensUsingCodeVerifier() {
        mockAPI.willReturnTokens()
            .willReturnUserInfo()
        val callback = MockAuthenticationCallback<Credentials>()
        client.token("code", "codeVerifier", "http://redirect.uri")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE)
        )
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("code", "code"))
        assertThat(body, Matchers.hasEntry("code_verifier", "codeVerifier"))
        assertThat(body, Matchers.hasEntry("redirect_uri", "http://redirect.uri"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasPayloadOfType(
                Credentials::class.java
            )
        )
    }

    @Test
    public fun shouldParseUnauthorizedPKCEError() {
        mockAPI.willReturnPlainTextUnauthorized()
        val callback = MockAuthenticationCallback<Credentials>()
        client.token("code", "codeVerifier", "http://redirect.uri")
            .start(callback)
        ShadowLooper.idleMainLooper()
        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/oauth/token"))
        val body = bodyFromRequest<String>(request)
        assertThat(
            body,
            Matchers.hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE)
        )
        assertThat(body, Matchers.hasEntry("client_id", CLIENT_ID))
        assertThat(body, Matchers.hasEntry("code", "code"))
        assertThat(body, Matchers.hasEntry("code_verifier", "codeVerifier"))
        assertThat(body, Matchers.hasEntry("redirect_uri", "http://redirect.uri"))
        assertThat(
            callback, AuthenticationCallbackMatcher.hasError(
                Credentials::class.java
            )
        )
        assertThat(
            callback.error.getDescription(),
            Matchers.`is`(Matchers.equalTo("Unauthorized"))
        )
    }

    private fun <T> bodyFromRequest(request: RecordedRequest): Map<String, T> {
        val mapType = object : TypeToken<Map<String?, T>?>() {}.type
        return gson.fromJson(request.body.readUtf8(), mapType)
    }

    private val defaultLocale: String
        get() {
            val language = Locale.getDefault().toString()
            return if (language.isNotEmpty()) language else DEFAULT_LOCALE_IF_MISSING
        }
    private val auth0: Auth0
        get() {
            val auth0 = Auth0(CLIENT_ID, mockAPI.domain, mockAPI.domain)
            auth0.networkingClient = testClient
            return auth0
        }

    private companion object {
        private const val CLIENT_ID = "CLIENTID"
        private const val DOMAIN = "samples.auth0.com"
        private const val PASSWORD = "123123123"
        private const val SUPPORT_AUTH0_COM = "support@auth0.com"
        private const val SUPPORT = "support"
        private const val MY_CONNECTION = "MyConnection"
        private const val FIRST_NAME = "John"
        private const val LAST_NAME = "Doe"
        private const val COMPANY = "Auth0"
        private const val OPENID = "openid"
        private const val DEFAULT_LOCALE_IF_MISSING = "en_US"
    }
}