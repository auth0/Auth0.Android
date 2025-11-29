package com.auth0.android.authentication.storage

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.util.Base64
import androidx.fragment.app.FragmentActivity
import com.auth0.android.Auth0
import com.auth0.android.NetworkErrorException
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.Jwt
import com.auth0.android.result.APICredentials
import com.auth0.android.result.ApiCredentialsMock
import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.auth0.android.result.SSOCredentials
import com.auth0.android.result.SSOCredentialsMock
import com.auth0.android.result.toAPICredentials
import com.auth0.android.util.Clock
import com.google.gson.Gson
import com.nhaarman.mockitokotlin2.KArgumentCaptor
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.argumentCaptor
import com.nhaarman.mockitokotlin2.eq
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.never
import com.nhaarman.mockitokotlin2.times
import com.nhaarman.mockitokotlin2.verify
import com.nhaarman.mockitokotlin2.verifyNoMoreInteractions
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.hamcrest.core.IsInstanceOf
import org.junit.Assert
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import java.lang.ref.WeakReference
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit


@RunWith(RobolectricTestRunner::class)
public class SecureCredentialsManagerTest {

    @Mock
    private lateinit var client: AuthenticationAPIClient

    @Mock
    private lateinit var storage: Storage

    @Mock
    private lateinit var callback: Callback<Credentials, CredentialsManagerException>

    @Mock
    private lateinit var ssoCallback: Callback<SSOCredentials, CredentialsManagerException>

    @Mock
    private lateinit var request: Request<Credentials, AuthenticationException>

    @Mock
    private lateinit var SSOCredentialsRequest: Request<SSOCredentials, AuthenticationException>

    @Mock
    private lateinit var apiCredentialsCallback: Callback<APICredentials, CredentialsManagerException>

    @Mock
    private lateinit var crypto: CryptoUtil

    @Mock
    private lateinit var jwtDecoder: JWTDecoder

    @Mock
    private lateinit var factory: LocalAuthenticationManagerFactory

    @Mock
    private lateinit var localAuthenticationManager: LocalAuthenticationManager

    private lateinit var weakFragmentActivity: WeakReference<FragmentActivity>

    private lateinit var fragmentActivity: FragmentActivity

    private val serialExecutor = Executor { runnable -> runnable.run() }

    private val credentialsCaptor: KArgumentCaptor<Credentials> = argumentCaptor()

    private val exceptionCaptor: KArgumentCaptor<CredentialsManagerException> = argumentCaptor()
    private val ssoCredentialsCaptor: KArgumentCaptor<SSOCredentials> = argumentCaptor()
    private val apiCredentialsCaptor: KArgumentCaptor<APICredentials> = argumentCaptor()

    private val stringCaptor: KArgumentCaptor<String> = argumentCaptor()

    @get:Rule
    public val exception: ExpectedException = ExpectedException.none()
    private lateinit var manager: SecureCredentialsManager
    private lateinit var gson: Gson
    private lateinit var auth0: Auth0

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        val activity =
            Robolectric.buildActivity(Activity::class.java).create().start().resume().get()
        val activityContext = Mockito.spy(activity)
        val kManager = mock<KeyguardManager>()
        Mockito.`when`(activityContext.getSystemService(Context.KEYGUARD_SERVICE))
            .thenReturn(kManager)
        Mockito.`when`(factory.create(any(), any(), any())).thenAnswer { invocation ->
            val callback = invocation.arguments[2] as Callback<Boolean, CredentialsManagerException>
            Mockito.`when`(localAuthenticationManager.resultCallback)
                .thenReturn(callback)
            return@thenAnswer localAuthenticationManager
        }
        fragmentActivity =
            Mockito.spy(
                Robolectric.buildActivity(FragmentActivity::class.java).create().start().resume()
                    .get()
            )
        weakFragmentActivity = WeakReference(fragmentActivity)
        auth0 = Mockito.spy(Auth0.getInstance("clientId", "domain"))
        Mockito.`when`(auth0.executor).thenReturn(serialExecutor)

        val secureCredentialsManager =
            SecureCredentialsManager(
                client,
                storage,
                crypto,
                jwtDecoder,
                auth0.executor,
                weakFragmentActivity,
                getAuthenticationOptions(),
                factory
            )
        manager = Mockito.spy(secureCredentialsManager)
        Mockito.doReturn(CredentialsMock.CURRENT_TIME_MS).`when`(manager).currentTimeInMillis
        gson = GsonProvider.gson
    }

    @Test
    public fun shouldCreateAManagerInstance() {
        val context: Context =
            Robolectric.buildActivity(Activity::class.java).create().start().resume().get()
        val storage: Storage = SharedPreferencesStorage(context)
        val manager = SecureCredentialsManager(
            context,
            auth0,
            storage,
            fragmentActivity,
            getAuthenticationOptions()
        )
        MatcherAssert.assertThat(manager, Is.`is`(Matchers.notNullValue()))
    }

    /*
     * SAVE SSO credentials test
     */

    @Test
    public fun shouldNotSaveIfThereIsErrorInGettingTheExistingCredentials() {
        verifyNoMoreInteractions(storage)
        val ssoCredentials = SSOCredentialsMock.create(
            "accessToken", "identityToken",
            "issuedTokenType", "tokenType", "refresh_token", 60
        )
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedJson = insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenThrow(CredentialsManagerException.NO_CREDENTIALS)
        manager.saveSsoCredentials(ssoCredentials)
        verify(storage, times(0)).store("com.auth0.credentials", storedJson)
        verify(storage, times(0)).store("com.auth0.credentials_can_refresh", true)
    }

    @Test
    public fun shouldSaveIfTheNewSSOCredentialRefreshAndIdTokenIsNotSameAsTheExistingOne() {
        verifyNoMoreInteractions(storage)
        val sessionTransferCredentials = SSOCredentialsMock.create(
            "accessToken", "identityToken",
            "issuedTokenType", "tokenType", "refresh_token", 60
        )
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        val newCredentials = CredentialsMock.create(
            "identityToken",
            "accessToken",
            "type",
            "refresh_token",
            Date(CredentialsMock.ONE_HOUR_AHEAD_MS),
            "scope"
        )
        val json = gson.toJson(newCredentials)
        Mockito.`when`(crypto.encrypt(any())).thenReturn(json.toByteArray())
        manager.saveSsoCredentials(sessionTransferCredentials)
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture())
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refresh_token"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`("identityToken"))
    }

    /*
     *  GET SSO credentials test
     */
    @Test
    public fun shouldThrowExceptionIfNoCredentialsExistOnGetSSOCredentials() {
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn(null)
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("No Credentials were previously set.")
        )
    }

    @Test
    public fun shouldThrowExceptionIfFetchingExistingCredentialsFailsOnGetSSOCredentials() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedJson = insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenThrow(CredentialsManagerException.CRYPTO_EXCEPTION)
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Any previously stored content is now lost. Please try saving the credentials again.")
        )
    }

    @Test
    public fun shouldThrowExceptionIfExistingCredentialsHasNoRefreshTokenOnGetSSOCredentials() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = false,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Credentials need to be renewed but no Refresh Token is available to renew them.")
        )
    }

    @Test
    public fun shouldFetchTheNewRefreshTokenOnGetSSOCredentials() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        Mockito.`when`(client.ssoExchange("refreshToken"))
            .thenReturn(SSOCredentialsRequest)
        Mockito.`when`(SSOCredentialsRequest.execute()).thenReturn(
            SSOCredentialsMock.create(
                "web-sso-token",
                "identity-token",
                "issued-token-type",
                "token-type",
                "refresh-token",
                60
            )
        )
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        val newCredentials = CredentialsMock.create(
            "idToken",
            "accessToken",
            "token-type",
            "refresh-token",
            Date(CredentialsMock.ONE_HOUR_AHEAD_MS),
            "scope"
        )
        val json = gson.toJson(newCredentials)
        Mockito.`when`(crypto.encrypt(any())).thenReturn(json.toByteArray())
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onSuccess(
            ssoCredentialsCaptor.capture()
        )
        val credentials = ssoCredentialsCaptor.firstValue
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`("web-sso-token"))
        MatcherAssert.assertThat(credentials.tokenType, Is.`is`("token-type"))
        MatcherAssert.assertThat(credentials.issuedTokenType, Is.`is`("issued-token-type"))
        MatcherAssert.assertThat(credentials.refreshToken, Is.`is`("refresh-token"))
        MatcherAssert.assertThat(credentials.expiresIn, Is.`is`(60))
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture())
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refresh-token"))
    }

    @Test
    public fun shouldFailWhenRefreshTokenExpiredOnGetSSOCredentials() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        Mockito.`when`(client.ssoExchange("refreshToken"))
            .thenReturn(SSOCredentialsRequest)
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        //Trigger failure
        val authenticationException = AuthenticationException(
            "invalid_grant",
            "Unknown or invalid refresh token."
        )
        Mockito.`when`(SSOCredentialsRequest.execute()).thenThrow(authenticationException)
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(authenticationException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("The exchange of the refresh token for SSO credentials failed.")
        )
    }

    @Test
    public fun shouldFailWhenUnexpectedErrorOccursOnGetSSOCredentials() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        Mockito.`when`(client.ssoExchange("refreshToken"))
            .thenReturn(SSOCredentialsRequest)
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        //Trigger failure
        val runtimeException = RuntimeException(
            "runtime exception"
        )
        Mockito.`when`(SSOCredentialsRequest.execute()).thenThrow(runtimeException)
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(runtimeException))
        MatcherAssert.assertThat(exception, Is.`is`(CredentialsManagerException.UNKNOWN_ERROR))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An unknown error has occurred while fetching the token. Please check the error cause for more details.")
        )
    }

    /*
     * AWAIT SSO credentials test
     */
    @Test
    @ExperimentalCoroutinesApi
    public fun shouldFailWhenNoExistingCredentialsWasSavedOnAwaitSSOCredentials(): Unit = runTest {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn(null)
        val exception = assertThrows(CredentialsManagerException::class.java) {
            runBlocking { manager.awaitSsoCredentials() }
        }
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("No Credentials were previously set.")
        )
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldThrowExceptionIfFetchingExistingCredentialsFailsOnAwaitSSOCredentials(): Unit =
        runTest {
            val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
            val storedJson = insertTestCredentials(
                hasIdToken = true,
                hasAccessToken = true,
                hasRefreshToken = true,
                willExpireAt = expiresAt,
                scope = "scope"
            )
            Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
                .thenThrow(CredentialsManagerException.CRYPTO_EXCEPTION)
            val exception = assertThrows(CredentialsManagerException::class.java) {
                runBlocking { manager.awaitSsoCredentials() }
            }
            MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
            MatcherAssert.assertThat(
                exception.message,
                Is.`is`("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Any previously stored content is now lost. Please try saving the credentials again.")
            )
        }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldThrowExceptionIfExistingCredentialsHasNoRefreshTokenOnAwaitSSOCredentials(): Unit =
        runTest {
            val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
            insertTestCredentials(
                hasIdToken = true,
                hasAccessToken = true,
                hasRefreshToken = false,
                willExpireAt = expiresAt,
                scope = "scope"
            )
            manager.getSsoCredentials(ssoCallback)
            val exception = assertThrows(CredentialsManagerException::class.java) {
                runBlocking { manager.awaitSsoCredentials() }
            }
            MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
            MatcherAssert.assertThat(
                exception.message,
                Is.`is`("Credentials need to be renewed but no Refresh Token is available to renew them.")
            )
        }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldFetchTheNewRefreshTokenOnAwaitSSOCredentials(): Unit = runTest {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        Mockito.`when`(client.ssoExchange("refreshToken"))
            .thenReturn(SSOCredentialsRequest)
        Mockito.`when`(SSOCredentialsRequest.execute()).thenReturn(
            SSOCredentialsMock.create(
                "web-sso-token",
                "identity-token",
                "issued-token-type",
                "token-type",
                "refresh-token",
                60
            )
        )
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        val newCredentials = CredentialsMock.create(
            "idToken",
            "accessToken",
            "token-type",
            "refresh-token",
            Date(CredentialsMock.ONE_HOUR_AHEAD_MS),
            "scope"
        )
        val json = gson.toJson(newCredentials)
        Mockito.`when`(crypto.encrypt(any())).thenReturn(json.toByteArray())
        val credentials = runBlocking {
            manager.awaitSsoCredentials()
        }
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`("web-sso-token"))
        MatcherAssert.assertThat(credentials.tokenType, Is.`is`("token-type"))
        MatcherAssert.assertThat(credentials.issuedTokenType, Is.`is`("issued-token-type"))
        MatcherAssert.assertThat(credentials.refreshToken, Is.`is`("refresh-token"))
        MatcherAssert.assertThat(credentials.expiresIn, Is.`is`(60))
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture())
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refresh-token"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldFailWhenRefreshTokenExpiredOnAwaitSSOCredentials(): Unit = runTest {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        Mockito.`when`(client.ssoExchange("refreshToken"))
            .thenReturn(SSOCredentialsRequest)
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        //Trigger failure
        val authenticationException = AuthenticationException(
            "invalid_grant",
            "Unknown or invalid refresh token."
        )
        Mockito.`when`(SSOCredentialsRequest.execute()).thenThrow(authenticationException)
        val exception = assertThrows(CredentialsManagerException::class.java) {
            runBlocking { manager.awaitSsoCredentials() }
        }
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(authenticationException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("The exchange of the refresh token for SSO credentials failed.")
        )
    }

    @Test
    public fun shouldSaveApiCredentialsInStorage() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data"
        )
        val json = gson.toJson(apiCredentials)
        prepareJwtDecoderMock(Date(expirationTime))
        Mockito.`when`(crypto.encrypt(any())).thenReturn(json.toByteArray())
        val captor: KArgumentCaptor<String> = argumentCaptor()
        manager.saveApiCredentials(apiCredentials, "audience")
        verify(storage).store(eq("audience"), captor.capture())
        val encodedJson = captor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), APICredentials::class.java)
        Assert.assertEquals("apiAccessToken", storedCredentials.accessToken)
        Assert.assertEquals("type", storedCredentials.type)
        Assert.assertEquals(expirationTime, storedCredentials.expiresAt.time)
        Assert.assertEquals("read:data", storedCredentials.scope)
        verifyNoMoreInteractions(storage)
    }

    /*
     * SAVE Credentials tests
     */
    @Test
    public fun shouldSaveRefreshableCredentialsInStorage() {
        val sharedExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials = CredentialsMock.create(
            "idToken",
            "accessToken",
            "type",
            "refreshToken",
            Date(sharedExpirationTime),
            "scope"
        )
        val json = gson.toJson(credentials)
        prepareJwtDecoderMock(Date(sharedExpirationTime))
        Mockito.`when`(crypto.encrypt(json.toByteArray())).thenReturn(json.toByteArray())
        manager.saveCredentials(credentials)
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", sharedExpirationTime)
        verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", sharedExpirationTime)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(storedCredentials.expiresAt.time, Is.`is`(sharedExpirationTime))
        MatcherAssert.assertThat(storedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldSaveRefreshableCredentialsUsingAccessTokenExpForCacheExpirationInStorage() {
        val accessTokenExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials = CredentialsMock.create(
            "",
            "accessToken",
            "type",
            "refreshToken",
            Date(accessTokenExpirationTime),
            "scope"
        )
        val json = gson.toJson(credentials)
        prepareJwtDecoderMock(Date(accessTokenExpirationTime))
        Mockito.`when`(crypto.encrypt(json.toByteArray())).thenReturn(json.toByteArray())
        manager.saveCredentials(credentials)
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", accessTokenExpirationTime)
        verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", accessTokenExpirationTime)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`(""))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            storedCredentials.expiresAt.time,
            Is.`is`(accessTokenExpirationTime)
        )
        MatcherAssert.assertThat(storedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldSaveRefreshableCredentialsIgnoringIdTokenExpForCacheExpirationInStorage() {
        val accessTokenExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val idTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 2000 * 1000
        val credentials: Credentials = CredentialsMock.create(
            "idToken",
            "accessToken",
            "type",
            "refreshToken",
            Date(accessTokenExpirationTime),
            "scope"
        )
        val json = gson.toJson(credentials)
        prepareJwtDecoderMock(Date(idTokenExpirationTime))
        Mockito.`when`(crypto.encrypt(json.toByteArray())).thenReturn(json.toByteArray())
        manager.saveCredentials(credentials)
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", accessTokenExpirationTime)
        verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", accessTokenExpirationTime)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            storedCredentials.expiresAt.time,
            Is.`is`(accessTokenExpirationTime)
        )
        MatcherAssert.assertThat(storedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldSaveNonRefreshableCredentialsInStorage() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials =
            CredentialsMock.create(
                "idToken",
                "accessToken",
                "type",
                null,
                Date(expirationTime),
                "scope"
            )
        val json = gson.toJson(credentials)
        prepareJwtDecoderMock(Date(expirationTime))
        Mockito.`when`(crypto.encrypt(json.toByteArray())).thenReturn(json.toByteArray())
        manager.saveCredentials(credentials)
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", expirationTime)
        verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", expirationTime)
        verify(storage).store("com.auth0.credentials_can_refresh", false)
        verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(storedCredentials.expiresAt.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(storedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldClearStoredCredentialsAndThrowOnSaveOnCryptoException() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials = CredentialsMock.create(
            "idToken",
            "accessToken",
            "type",
            "refreshToken",
            Date(expirationTime),
            "scope"
        )
        prepareJwtDecoderMock(Date(expirationTime))
        Mockito.`when`(crypto.encrypt(any())).thenThrow(
            CryptoException("err", null)
        )
        var exception: CredentialsManagerException? = null
        try {
            manager.saveCredentials(credentials)
        } catch (e: CredentialsManagerException) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception!!.isDeviceIncompatible, Is.`is`(false))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Any previously stored content is now lost. Please try saving the credentials again.")
        )
        verify(storage).remove("com.auth0.credentials")
        verify(storage).remove("com.auth0.credentials_expires_at")
        verify(storage).remove("com.auth0.credentials_can_refresh")
    }

    @Test
    public fun shouldThrowOnSaveOnIncompatibleDeviceException() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials = CredentialsMock.create(
            "idToken",
            "accessToken",
            "type",
            "refreshToken",
            Date(expirationTime),
            "scope"
        )
        prepareJwtDecoderMock(Date(expirationTime))
        Mockito.`when`(crypto.encrypt(any()))
            .thenThrow(IncompatibleDeviceException(null))
        var exception: CredentialsManagerException? = null
        try {
            manager.saveCredentials(credentials)
        } catch (e: CredentialsManagerException) {
            exception = e
        }
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception!!.isDeviceIncompatible, Is.`is`(true))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("This device is not compatible with the SecureCredentialsManager class.")
        )
    }

    @Test
    public fun shouldThrowOnSaveIfCredentialsDoesNotHaveIdTokenOrAccessToken() {
        exception.expect(CredentialsManagerException::class.java)
        exception.expectMessage("Credentials must have a valid access_token or id_token value.")
        val credentials: Credentials =
            CredentialsMock.create("", "", "type", "refreshToken", Date(), "scope")
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSaveIfCredentialsHaveAccessTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock.create("", "accessToken", "type", "refreshToken", Date(), "scope")
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(byteArrayOf(12, 34, 56, 78))
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSaveIfCredentialsHaveIdTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock.create("idToken", "", "type", "refreshToken", Date(), "scope")
        prepareJwtDecoderMock(Date())
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(byteArrayOf(12, 34, 56, 78))
        manager.saveCredentials(credentials)
    }

    /*
     * GET Credentials tests
     */
    @Test
    public fun shouldClearStoredCredentialsAndFailOnGetCredentialsWhenCryptoExceptionIsThrown() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedJson = insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenThrow(CryptoException("err", null))
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.cause, IsInstanceOf.instanceOf(
                CryptoException::class.java
            )
        )
        MatcherAssert.assertThat(
            exception.message, Is.`is`(
                "A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. " +
                        "Any previously stored content is now lost. Please try saving the credentials again."
            )
        )
        verify(storage).remove("com.auth0.credentials")
        verify(storage).remove("com.auth0.credentials_expires_at")
        verify(storage).remove("com.auth0.credentials_can_refresh")
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenIncompatibleDeviceExceptionIsThrown() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedJson = insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenThrow(IncompatibleDeviceException(null))
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.cause, IsInstanceOf.instanceOf(
                IncompatibleDeviceException::class.java
            )
        )
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("This device is not compatible with the SecureCredentialsManager class.")
        )
        verify(storage, never()).remove("com.auth0.credentials")
        verify(storage, never()).remove("com.auth0.credentials_expires_at")
        verify(storage, never()).remove("com.auth0.credentials_can_refresh")
    }

    @Test
    public fun shouldFailOnSavingRefreshedCredentialsInGetCredentialsWhenCryptoExceptionIsThrown() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope") // "scope" is set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)

        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenThrow(CryptoException("CryptoException is thrown"))
        manager.getCredentials(
            "different scope",
            0,
            callback
        ) // minTTL of 0 seconds (default)
        verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )

        // Verify the returned credentials are the latest
        val exception = exceptionCaptor.firstValue
        val retrievedCredentials = exception.refreshedCredentials
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An error occurred while saving the refreshed Credentials.")
        )
        MatcherAssert.assertThat(
            exception.cause!!.message,
            Is.`is`("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Any previously stored content is now lost. Please try saving the credentials again.")
        )
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials!!.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("different scope"))
    }

    @Test
    public fun shouldFailOnSavingRefreshedCredentialsInGetCredentialsWhenIncompatibleDeviceExceptionIsThrown() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope") // "scope" is set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)

        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenThrow(IncompatibleDeviceException(Exception()))
        manager.getCredentials(
            "different scope",
            0,
            callback
        ) // minTTL of 0 seconds (default)
        verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )

        // Verify the returned credentials are the latest
        val exception = exceptionCaptor.firstValue
        val retrievedCredentials = exception.refreshedCredentials
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An error occurred while saving the refreshed Credentials.")
        )
        MatcherAssert.assertThat(
            exception.cause!!.message,
            Is.`is`("This device is not compatible with the SecureCredentialsManager class.")
        )
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials!!.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("different scope"))
    }


    @Test
    public fun shouldFailWithoutRefreshedCredentialsInExceptionOnSavingRefreshedCredentialsInGetCredentialsWhenDifferentExceptionIsThrown() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope") // "scope" is set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        // Trigger success
        val expectedCredentials =
            Credentials("", "", "newType", "refreshToken", newDate, "different scope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)

        manager.getCredentials(
            "different scope",
            0,
            callback
        ) // minTTL of 0 seconds (default)
        verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )

        // Verify the returned credentials are the latest
        val exception = exceptionCaptor.firstValue
        val retrievedCredentials = exception.refreshedCredentials
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An error occurred while saving the refreshed Credentials.")
        )
        MatcherAssert.assertThat(
            exception.cause!!.message,
            Is.`is`("Credentials must have a valid access_token or id_token value.")
        )
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.nullValue()))
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenNoAccessTokenOrIdTokenWasSaved() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(false, false, true, expiresAt, "scope")
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.message, Is.`is`("No Credentials were previously set."))
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenExpiredAndNoRefreshTokenWasSaved() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) //Same as current time --> expired
        insertTestCredentials(true, true, false, expiresAt, "scope")
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Credentials need to be renewed but no Refresh Token is available to renew them.")
        )
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorage() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, true, true, expiresAt, "scope")
        manager.getCredentials(callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitNonExpiredCredentialsFromStorage(): Unit = runTest {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, true, true, expiresAt, "scope")
        val retrievedCredentials = manager.awaitCredentials()
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldFailOnAwaitCredentialsWhenExpiredAndNoRefreshTokenWasSaved(): Unit = runTest {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) //Same as current time --> expired
        insertTestCredentials(true, true, false, expiresAt, "scope")
        val exception = assertThrows(CredentialsManagerException::class.java) {
            runBlocking { manager.awaitCredentials() }
        }
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Credentials need to be renewed but no Refresh Token is available to renew them.")
        )
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, false, true, expiresAt, "scope")
        manager.getCredentials(callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`(""))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorageWhenOnlyAccessTokenIsAvailable() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        manager.getCredentials(callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`(""))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldRenewCredentialsWithMinTtl() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) // expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope")
        val newDate =
            Date(CredentialsMock.CURRENT_TIME_MS + 61 * 1000) // new token expires in minTTL + 1 seconds
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.continueGetCredentials(
            null,
            60,
            emptyMap(),
            emptyMap(),
            false,
            callback
        ) // minTTL of 1 minute
        verify(request, never())
            .addParameter(eq("scope"), anyString())
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verify(storage, never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val renewedStoredCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(renewedStoredCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(renewedStoredCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(renewedStoredCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(renewedStoredCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt,
            Is.`is`(Matchers.notNullValue())
        )
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenReceivedTokenHasLowerTtl() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) // expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope")
        val newDate =
            Date(CredentialsMock.CURRENT_TIME_MS + 59 * 1000) // new token expires in minTTL - 1 seconds
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        // Trigger failure
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.continueGetCredentials(
            null,
            60,
            emptyMap(),
            emptyMap(),
            false,
            callback
        ) // minTTL of 1 minute
        verify(request, never())
            .addParameter(eq("scope"), anyString())
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("The lifetime of the renewed Access Token (1) is less than the minTTL requested (60). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.")
        )
        verify(storage, never())
            .store(eq("com.auth0.credentials"), anyString())
        verify(storage, never()).store(
            eq("com.auth0.credentials_expires_at"),
            anyLong()
        )
        verify(storage, never()).store(
            eq("com.auth0.credentials_can_refresh"),
            anyBoolean()
        )
        verify(storage, never()).remove(anyString())
    }

    @Test
    public fun shouldRenewCredentialsWhenScopeHasChanged() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope") // "scope" is set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)

        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.getCredentials(
            "different scope",
            0,
            callback
        ) // minTTL of 0 seconds (default)
        verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verify(storage, never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("different scope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val renewedStoredCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(renewedStoredCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(renewedStoredCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(renewedStoredCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(renewedStoredCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt,
            Is.`is`(Matchers.notNullValue())
        )
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("different scope"))
    }

    @Test
    public fun shouldRenewCredentialsIfSavedScopeIsNullAndRequiredScopeIsNotNull() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(false, true, true, expiresAt, null) // "scope" is not set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.getCredentials(
            "different scope",
            0,
            callback
        ) // minTTL of 0 seconds (default)
        verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verify(storage, never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("different scope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val renewedStoredCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(renewedStoredCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(renewedStoredCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(renewedStoredCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(renewedStoredCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt,
            Is.`is`(Matchers.notNullValue())
        )
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("different scope"))
    }

    @Test
    public fun shouldRenewExpiredCredentialsWhenScopeHasChanged() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt =
            Date(CredentialsMock.CURRENT_TIME_MS) // current time means expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope")
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)

        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.getCredentials(
            "different scope",
            0,
            callback
        ) // minTTL of 0 seconds (default)
        verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verify(storage, never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("different scope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val renewedStoredCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(renewedStoredCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(renewedStoredCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(renewedStoredCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(renewedStoredCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt,
            Is.`is`(Matchers.notNullValue())
        )
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("different scope"))
    }

    @Test
    public fun shouldNotHaveCredentialsWhenAccessTokenWillExpireAndNoRefreshTokenIsAvailable() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_access_token_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        Assert.assertFalse(manager.hasValidCredentials(ONE_HOUR_SECONDS))
    }

    @Test
    public fun shouldGetAndSuccessfullyRenewExpiredCredentials() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt =
            Date(CredentialsMock.CURRENT_TIME_MS) // current time means expired credentials
        insertTestCredentials(false, true, true, expiresAt, "scope")
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        verify(request, never())
            .addParameter(eq("scope"), anyString())
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)

        // Trigger success
//        val renewedCredentials =
//            Credentials("newId", "newAccess", "newType", null, newDate, "newScope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.getCredentials(callback)
//        requestCallbackCaptor.firstValue.onSuccess(renewedCredentials)TODO poovam
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verify(storage, never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val renewedStoredCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(renewedStoredCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(renewedStoredCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(renewedStoredCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(renewedStoredCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt,
            Is.`is`(Matchers.notNullValue())
        )
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndSuccessfullyRenewExpiredCredentialsWithRefreshTokenRotation() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        //Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)

        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.getCredentials(callback)
        verify(request, never())
            .addParameter(eq("scope"), anyString())
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        verify(storage).store("com.auth0.credentials_can_refresh", true)
        verify(storage, never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("rotatedRefreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.firstValue
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val renewedStoredCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(renewedStoredCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(renewedStoredCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(
            renewedStoredCredentials.refreshToken,
            Is.`is`("rotatedRefreshToken")
        )
        MatcherAssert.assertThat(renewedStoredCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt,
            Is.`is`(Matchers.notNullValue())
        )
        MatcherAssert.assertThat(
            renewedStoredCredentials.expiresAt.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenRefreshTokenExpired() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        //Trigger failure
        val authenticationException = AuthenticationException(
            "invalid_grant",
            "Unknown or invalid refresh token."
        )
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        verify(storage, never())
            .store(anyString(), anyLong())
        verify(storage, never())
            .store(anyString(), anyInt())
        verify(storage, never())
            .store(anyString(), anyString())
        verify(storage, never())
            .store(anyString(), anyBoolean())
        verify(storage, never()).remove(anyString())
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(authenticationException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An error occurred while trying to use the Refresh Token to renew the Credentials.")
        )
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenUserIsDeleted() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        //Trigger failure
        val authenticationException = AuthenticationException(
            mapOf(
                "error" to "invalid_grant",
                "error_description" to "The refresh_token was generated for a user who doesn't exist anymore."
            ), 403
        )
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        verify(storage, never())
            .store(anyString(), anyLong())
        verify(storage, never())
            .store(anyString(), anyInt())
        verify(storage, never())
            .store(anyString(), anyString())
        verify(storage, never())
            .store(anyString(), anyBoolean())
        verify(storage, never()).remove(anyString())
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(authenticationException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An error occurred while trying to use the Refresh Token to renew the Credentials.")
        )
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenNetworkIsNotAvailable() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        //Trigger failure
        val authenticationException = AuthenticationException(
            "Failed to execute the network request", NetworkErrorException(mock())
        )
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        verify(storage, never())
            .store(anyString(), anyLong())
        verify(storage, never())
            .store(anyString(), anyInt())
        verify(storage, never())
            .store(anyString(), anyString())
        verify(storage, never())
            .store(anyString(), anyBoolean())
        verify(storage, never()).remove(anyString())
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(authenticationException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to execute the network request.")
        )
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenApiErrorOccurs() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        //Trigger failure
        val authenticationException =
            AuthenticationException("Something went wrong", mock<Exception>())
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        verify(storage, never())
            .store(anyString(), anyLong())
        verify(storage, never())
            .store(anyString(), anyInt())
        verify(storage, never())
            .store(anyString(), anyString())
        verify(storage, never())
            .store(anyString(), anyBoolean())
        verify(storage, never()).remove(anyString())
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(authenticationException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An error occurred while processing the request.")
        )
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenAnyUnexpectedErrorOccurs() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        //Trigger failure
        val runtimeError =
            RuntimeException("Something went wrong")
        Mockito.`when`(request.execute()).thenThrow(runtimeError)
        manager.getCredentials(callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        verify(storage, never())
            .store(anyString(), anyLong())
        verify(storage, never())
            .store(anyString(), anyInt())
        verify(storage, never())
            .store(anyString(), anyString())
        verify(storage, never())
            .store(anyString(), anyBoolean())
        verify(storage, never()).remove(anyString())
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception, Is.`is`(CredentialsManagerException.UNKNOWN_ERROR))
        MatcherAssert.assertThat(exception.cause, Is.`is`(runtimeError))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An unknown error has occurred while fetching the token. Please check the error cause for more details.")
        )
    }

    /**
     * Testing that getCredentials execution from multiple threads via multiple instances of SecureCredentialsManager should trigger only one network request.
     */
    @Test
    public fun shouldSynchronizeGetCredentialsAccessAcrossThreadsAndInstances() {

        val expiredCredentials = Credentials(
            "",
            "accessToken",
            "type",
            "refreshToken",
            Date(CredentialsMock.CURRENT_TIME_MS),
            "scope"
        )
        val renewedCredentials =
            Credentials(
                "newId",
                "newAccess",
                "newType",
                "rotatedRefreshToken",
                Date(CredentialsMock.ONE_HOUR_AHEAD_MS),
                "newScope"
            )
        Mockito.`when`(
            client.renewAuth(refreshToken = "refreshToken")
        ).thenReturn(request)
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val serialExecutor = Executors.newSingleThreadExecutor()
        Mockito.`when`(auth0.executor).thenReturn(serialExecutor)
        val executor: ExecutorService = Executors.newFixedThreadPool(5)
        val latch = CountDownLatch(5)
        val context: Context =
            Robolectric.buildActivity(Activity::class.java).create().start().resume().get()
        val storage = SharedPreferencesStorage(
            context = context,
            sharedPreferencesName = "com.auth0.android.storage.SecureCredentialsManagerTest"
        )
        val cryptoMock = Mockito.mock(CryptoUtil::class.java)
        Mockito.`when`(cryptoMock.encrypt(any())).thenAnswer {
            val input = it.arguments[0] as ByteArray
            input
        }
        Mockito.`when`(cryptoMock.decrypt(any())).thenAnswer {
            val input = it.arguments[0] as ByteArray
            input
        }
        val secureCredsManager =
            SecureCredentialsManager(client, storage, cryptoMock, jwtDecoder, auth0.executor)
        secureCredsManager.saveCredentials(expiredCredentials)
        repeat(5) {
            executor.submit {
                val secureCredsManager =
                    SecureCredentialsManager(
                        client,
                        storage,
                        cryptoMock,
                        jwtDecoder,
                        auth0.executor,
                    )
                secureCredsManager.getCredentials(object :
                    Callback<Credentials, CredentialsManagerException> {
                    override fun onFailure(error: CredentialsManagerException) {
                        throw error
                    }

                    override fun onSuccess(result: Credentials) {
                        // Verify all instances retrieved the same credentials
                        MatcherAssert.assertThat(
                            renewedCredentials.accessToken,
                            Is.`is`(result.accessToken)
                        )
                        MatcherAssert.assertThat(
                            renewedCredentials.idToken,
                            Is.`is`(result.idToken)
                        )
                        MatcherAssert.assertThat(
                            renewedCredentials.refreshToken,
                            Is.`is`(result.refreshToken)
                        )
                        MatcherAssert.assertThat(renewedCredentials.type, Is.`is`(result.type))
                        MatcherAssert.assertThat(
                            renewedCredentials.expiresAt,
                            Is.`is`(result.expiresAt)
                        )
                        MatcherAssert.assertThat(
                            renewedCredentials.scope,
                            Is.`is`(result.scope)
                        )
                        latch.countDown()
                    }
                })
            }
        }
        latch.await() // Wait for all threads to finish
        Mockito.verify(client, Mockito.times(1))
            .renewAuth(
                refreshToken = "refreshToken"
            ) // verify that api client's renewAuth is called only once
        Mockito.verify(request, Mockito.times(1)).execute() // Verify single network request
    }

    /*
     * CLEAR Credentials tests
     */
    @Test
    public fun shouldClearCredentials() {
        manager.clearCredentials()
        verify(storage).remove("com.auth0.credentials")
        verify(storage).remove("com.auth0.credentials_expires_at")
        verify(storage).remove("com.auth0.credentials_access_token_expires_at")
        verify(storage).remove("com.auth0.credentials_can_refresh")
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldClearApiCredentials() {
        val captor = argumentCaptor<String>()
        manager.clearApiCredentials("audience")
        verify(storage).remove(captor.capture())
        Assert.assertEquals("audience", captor.firstValue)
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldSaveEncryptedApiCredentialsWithScopeAsKey() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data write:data"
        )
        val json = gson.toJson(apiCredentials)
        Mockito.`when`(crypto.encrypt(json.toByteArray())).thenReturn(json.toByteArray())

        manager.saveApiCredentials(apiCredentials, "audience", "read:data write:data")

        verify(crypto).encrypt(json.toByteArray())
        verify(storage).store(
            eq("audience::read:data::write:data"),
            anyString()
        )
    }

    @Test
    public fun shouldSaveEncryptedApiCredentialsWithoutScopeUsingOnlyAudience() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data"
        )
        val json = gson.toJson(apiCredentials)
        Mockito.`when`(crypto.encrypt(json.toByteArray())).thenReturn(json.toByteArray())

        manager.saveApiCredentials(apiCredentials, "audience", null)

        verify(crypto).encrypt(json.toByteArray())
        verify(storage).store(eq("audience"), anyString())
    }

    @Test
    public fun shouldSaveEncryptedApiCredentialsWithDifferentScopesUnderDifferentKeys() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials1 = APICredentials(
            accessToken = "apiAccessToken1",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data"
        )
        val apiCredentials2 = APICredentials(
            accessToken = "apiAccessToken2",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "write:data"
        )
        val json1 = gson.toJson(apiCredentials1)
        val json2 = gson.toJson(apiCredentials2)
        Mockito.`when`(crypto.encrypt(json1.toByteArray())).thenReturn(json1.toByteArray())
        Mockito.`when`(crypto.encrypt(json2.toByteArray())).thenReturn(json2.toByteArray())

        manager.saveApiCredentials(apiCredentials1, "audience", "read:data")
        manager.saveApiCredentials(apiCredentials2, "audience", "write:data")

        verify(storage).store(eq("audience::read:data"), anyString())
        verify(storage).store(eq("audience::write:data"), anyString())
    }

    @Test
    public fun shouldThrowIncompatibleDeviceExceptionOnSaveApiCredentials() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data"
        )
        val json = gson.toJson(apiCredentials)
        Mockito.`when`(crypto.encrypt(json.toByteArray()))
            .thenThrow(IncompatibleDeviceException(RuntimeException()))

        val exception = assertThrows(CredentialsManagerException::class.java) {
            manager.saveApiCredentials(apiCredentials, "audience", "read:data")
        }

        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.isDeviceIncompatible, Is.`is`(true))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("This device is not compatible with the SecureCredentialsManager class.")
        )
    }

    @Test
    public fun shouldClearAndThrowCryptoExceptionOnSaveApiCredentials() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data"
        )
        val json = gson.toJson(apiCredentials)
        Mockito.`when`(crypto.encrypt(json.toByteArray()))
            .thenThrow(CryptoException("Encryption failed", RuntimeException()))

        val exception = assertThrows(CredentialsManagerException::class.java) {
            manager.saveApiCredentials(apiCredentials, "audience", "read:data")
        }

        verify(storage).remove("audience::read:data")
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.isDeviceIncompatible, Is.`is`(false))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Any previously stored content is now lost. Please try saving the credentials again.")
        )
    }

    @Test
    public fun shouldClearApiCredentialsWithScopeInSecureManager() {
        manager.clearApiCredentials("audience", "read:data write:data")
        verify(storage).remove("audience::read:data::write:data")
    }

    @Test
    public fun shouldClearApiCredentialsWithoutScopeUsingAudienceOnlyInSecureManager() {
        manager.clearApiCredentials("audience", null)
        verify(storage).remove("audience")
    }

    @Test
    public fun shouldClearApiCredentialsWithDefaultNullScopeInSecureManager() {
        manager.clearApiCredentials("audience")
        verify(storage).remove("audience")
    }

    @Test
    public fun shouldGetEncryptedApiCredentialsWithSpecificScope() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            accessToken = "apiToken",
            expiresAt = Date(accessTokenExpiry),
            scope = "read:data"
        )
        val json = gson.toJson(apiCredentials)
        val encryptedJson = Base64.encodeToString(json.toByteArray(), Base64.DEFAULT)
        Mockito.`when`(storage.retrieveString("audience::read:data"))
            .thenReturn(encryptedJson)
        Mockito.`when`(crypto.decrypt(any()))
            .thenReturn(json.toByteArray())

        manager.getApiCredentials("audience", "read:data", callback = apiCredentialsCallback)

        verify(apiCredentialsCallback).onSuccess(apiCredentialsCaptor.capture())
        val retrievedCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("apiToken"))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("read:data"))
    }

    @Test
    public fun shouldGetEncryptedApiCredentialsWithoutScopeFromAudienceKey() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            accessToken = "apiToken",
            expiresAt = Date(accessTokenExpiry),
            scope = "openid"
        )
        val json = gson.toJson(apiCredentials)
        val encryptedJson = Base64.encodeToString(json.toByteArray(), Base64.DEFAULT)
        Mockito.`when`(storage.retrieveString("audience"))
            .thenReturn(encryptedJson)
        Mockito.`when`(crypto.decrypt(any()))
            .thenReturn(json.toByteArray())

        manager.getApiCredentials("audience", null, callback = apiCredentialsCallback)

        verify(apiCredentialsCallback).onSuccess(apiCredentialsCaptor.capture())
        val retrievedCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("apiToken"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitEncryptedApiCredentialsWithSpecificScope(): Unit = runTest {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            accessToken = "apiToken",
            expiresAt = Date(accessTokenExpiry),
            scope = "read:data"
        )
        val json = gson.toJson(apiCredentials)
        val encryptedJson = Base64.encodeToString(json.toByteArray(), Base64.DEFAULT)
        Mockito.`when`(storage.retrieveString("audience::read:data"))
            .thenReturn(encryptedJson)
        Mockito.`when`(crypto.decrypt(any()))
            .thenReturn(json.toByteArray())

        val result = manager.awaitApiCredentials("audience", "read:data")

        MatcherAssert.assertThat(result.accessToken, Is.`is`("apiToken"))
        MatcherAssert.assertThat(result.scope, Is.`is`("read:data"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitAndRenewEncryptedApiCredentialsWithScope(): Unit = runTest {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("audience::write:data"))
            .thenReturn(null)

        val existingCredentials = CredentialsMock.create(
            idToken = "idToken",
            accessToken = "accessToken",
            type = "type",
            refreshToken = "refreshToken",
            expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS),
            scope = "scope"
        )
        val existingJson = gson.toJson(existingCredentials)
        val encryptedExisting = Base64.encodeToString(existingJson.toByteArray(), Base64.DEFAULT)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn(encryptedExisting)
        Mockito.`when`(crypto.decrypt(any()))
            .thenReturn(existingJson.toByteArray())

        Mockito.`when`(client.renewAuth("refreshToken", "audience", "write:data"))
            .thenReturn(request)

        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        val renewedCredentials = Credentials(
            "newId", "newAccess", "newType", null, newDate, "write:data"
        )
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)

        val updatedExistingTokenJson = gson.toJson(existingCredentials.copy(idToken = "newId"))
        val renewedJson = gson.toJson(renewedCredentials.toAPICredentials())
        Mockito.`when`(crypto.encrypt(updatedExistingTokenJson.toByteArray()))
            .thenReturn(updatedExistingTokenJson.toByteArray())

        Mockito.`when`(crypto.encrypt(renewedJson.toByteArray()))
            .thenReturn(renewedJson.toByteArray())

        val result = manager.awaitApiCredentials("audience", "write:data")

        MatcherAssert.assertThat(result.scope, Is.`is`("write:data"))
        MatcherAssert.assertThat(result.accessToken, Is.`is`("newAccess"))
    }

    /*
     * HAS Credentials tests
     */
    @Test
    public fun shouldPreventLoggingOutUsersWhenAccessTokenExpiresAtWasNotSaved() {
        val cacheExpiresAt = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(cacheExpiresAt)
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_access_token_expires_at"))
            .thenReturn(null)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    @Test
    public fun shouldHaveCredentialsWhenTokenHasNotExpired() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        MatcherAssert.assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        MatcherAssert.assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), Is.`is`(true))
    }

    @Test
    public fun shouldNotHaveCredentialsWhenTokenHasExpiredAndNoRefreshTokenIsAvailable() {
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_access_token_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
    }

    @Test
    public fun shouldHaveCredentialsWhenTokenHasExpiredButRefreshTokenIsAvailable() {
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_access_token_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(true)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\", \"refresh_token\":\"refreshToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\", \"refresh_token\":\"refreshToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    @Test
    public fun shouldHaveCredentialsWhenTheAliasUsedHasNotBeenMigratedYet() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    @Test
    public fun shouldHaveCredentialsWhenTheAliasUsedHasNotBeenSetYet() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    //APICredentials

    @Test
    public fun shouldGetExistingAPICredentialsIfAlreadyPresentAndNotExpired() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            "token", "type",
            Date(accessTokenExpiry), "scope"
        )
        val storedJson = gson.toJson(apiCredentials)
        val encoded = String(Base64.encode(storedJson.toByteArray(), Base64.DEFAULT))
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenReturn(storedJson.toByteArray())
        Mockito.`when`(storage.retrieveString("audience::scope")).thenReturn(encoded)
        manager.getApiCredentials("audience", "scope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(apiCredentialsCaptor.capture())
        val retrievedCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        Assert.assertEquals(retrievedCredentials.accessToken, apiCredentials.accessToken)
    }

    @Test
    public fun shouldThrowExceptionIfThereISNoRefreshTokenToGetNewApiToken() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = false,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        manager.getApiCredentials(audience = "audience", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onFailure(exceptionCaptor.capture())
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Credentials need to be renewed but no Refresh Token is available to renew them.")
        )
    }


    @Test
    public fun shouldRenewApiCredentialsIfThereIsNoExistingApiCredentials() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        Mockito.`when`(storage.retrieveString("audience")).thenReturn(null)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(
            hasIdToken = true,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        )
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience", "newScope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val updatedCredentials = renewedCredentials.copy(refreshToken = "refreshToken")
        val expectedJson = gson.toJson(updatedCredentials)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(expectedJson.toByteArray())
        manager.getApiCredentials("audience", "newScope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture())
        MatcherAssert.assertThat(stringCaptor.firstValue, Is.`is`(Matchers.notNullValue()))
        val credentials = gson.fromJson(expectedJson, Credentials::class.java)
        Assert.assertEquals("refreshToken", credentials.refreshToken)
        // Verify the returned credentials are the latest
        val newAPiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldRenewApiCredentialsIfCurrentTokenHasExpired() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val accessTokenExpiry = CredentialsMock.CURRENT_TIME_MS - 3000
        insertTestCredentials(
            true,
            true,
            true,
            Date(CredentialsMock.CURRENT_TIME_MS + 10 * 1000),
            "scope"
        )
        insertTestApiCredentials("audience", true, Date(accessTokenExpiry), "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience", "scope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(expectedJson.toByteArray())
        manager.getApiCredentials("audience", "scope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        val newAPiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldRenewApiCredentialsIfCurrentTokenWillExpireWithInMinTtl() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val accessTokenExpiry = CredentialsMock.CURRENT_TIME_MS - 10000
        insertTestCredentials(
            true,
            true,
            true,
            Date(CredentialsMock.CURRENT_TIME_MS + 10 * 1000),
            "scope"
        )
        insertTestApiCredentials("audience", true, Date(accessTokenExpiry), "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience", "scope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(expectedJson.toByteArray())
        manager.getApiCredentials(
            "audience",
            "scope",
            minTtl = 10,
            callback = apiCredentialsCallback
        )
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        val newAPiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldRenewApiCredentialsIfSavedScopeIsDifferentFromRequiredScope() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val accessTokenExpiry = CredentialsMock.CURRENT_TIME_MS
        insertTestCredentials(
            true,
            true,
            true,
            Date(CredentialsMock.CURRENT_TIME_MS + 10 * 1000),
            "scope"
        )
        insertTestApiCredentials("audience", true, Date(accessTokenExpiry), "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience", "newScope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(expectedJson.toByteArray())
        manager.getApiCredentials("audience", "newScope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        val newAPiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldReplaceTheExistingRefreshTokenIfaNewOneIsObtainedInApiCredentials() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val accessTokenExpiry = CredentialsMock.CURRENT_TIME_MS
        insertTestCredentials(
            true,
            true,
            true,
            Date(CredentialsMock.CURRENT_TIME_MS + 10 * 1000),
            "scope"
        )
        insertTestApiCredentials("audience", true, Date(accessTokenExpiry), "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience", "newScope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "newRefreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(expectedJson.toByteArray())
        manager.getApiCredentials("audience", "newScope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        // Verify the returned credentials are the latest
        val newAPiCredentials = apiCredentialsCaptor.firstValue
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture())
        val encodedJson = stringCaptor.firstValue
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val newCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        Assert.assertEquals("newRefreshToken", newCredentials.refreshToken)
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldThrowExceptionIfTheNewAPiCredentialTokenHasLowerLifetimeThanMinTTLRequested() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        insertTestCredentials(
            true,
            true,
            true,
            Date(CredentialsMock.CURRENT_TIME_MS + 10 * 1000),
            "scope"
        )
        Mockito.`when`(storage.retrieveString("audience")).thenReturn(null)
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience", "newScope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.CURRENT_TIME_MS + 1 * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "newRefreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(expectedJson.toByteArray())
        manager.getApiCredentials(
            "audience",
            "newScope",
            minTtl = 1,
            callback = apiCredentialsCallback
        )
        verify(apiCredentialsCallback).onFailure(
            exceptionCaptor.capture()
        )

        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitNonExpiredApiCredentialsFromStorage(): Unit = runTest {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        insertTestApiCredentials(
            "audience1", true, Date(accessTokenExpiry), "scope"
        )
        val retrievedCredentials = manager.awaitApiCredentials("audience1")
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        Assert.assertEquals("accessToken", retrievedCredentials.accessToken)
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitNewApiCredentialsIfOneIsNotStored(): Unit = runTest {
        verifyNoMoreInteractions(client)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        insertTestCredentials(
            true, true, true, Date(CredentialsMock.ONE_HOUR_AHEAD_MS), null
        )

        Mockito.`when`(storage.retrieveString("audience")).thenReturn(null)

        Mockito.`when`(
            client.renewAuth("refreshToken", "audience")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", null, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(expectedJson.toByteArray())
        val retrievedCredentials = manager.awaitApiCredentials("audience")
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        Assert.assertEquals(retrievedCredentials.accessToken, renewedCredentials.accessToken)
    }

    /*
     * Authentication tests
     */

    @Test
    public fun shouldGetCredentialsWithAuthentication() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)

        manager.getCredentials(callback)
        verify(callback).onSuccess(credentialsCaptor.capture())
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldNotGetCredentialsWhenCredentialsHaveExpired() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val credentialsExpiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedExpiresAt = Date(CredentialsMock.CURRENT_TIME_MS - ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, true, false, credentialsExpiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_access_token_expires_at"))
            .thenReturn(storedExpiresAt.time)
        manager.getCredentials(callback)
        // Should fail because of expired credentials
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.message, Is.`is`("No Credentials were previously set."))
    }

    @Test
    public fun shouldNotGetCredentialsWhenCredentialsWereCleared() {
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onSuccess(true)
        }
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials")).thenReturn(null)
        manager.getCredentials(callback)
        // Return null for Credentials JSON since it is cleared
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.message, Is.`is`("No Credentials were previously set."))
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricHardwareUnavailable() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_HW_UNAVAILABLE
            )
        }
        manager.getCredentials(callback)
        // Should fail because of unavailable hardware
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Cannot authenticate because the hardware is unavailable. Try again later.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsUnableToProcess() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_UNABLE_TO_PROCESS
            )
        }
        manager.getCredentials(callback)
        // Should fail because of unable to process
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the sensor was unable to process the current image.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsTimeout() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_TIMEOUT
            )
        }
        manager.getCredentials(callback)
        // Should fail because of timeout
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the operation timed out.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToNoSpaceOnDevice() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NO_SPACE
            )
        }
        manager.getCredentials(callback)
        // Should fail because of no space
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because there is not enough storage remaining on the device.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToCancellation() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_CANCELED
            )
        }
        manager.getCredentials(callback)
        // Should fail because of cancellation
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the operation was canceled as the biometric sensor is unavailable, this may happen when the user is switched, the device is locked.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToLockOut() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT
            )
        }
        manager.getCredentials(callback)
        // Should fail because of lockout
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the user has been temporarily locked out, this occurs after 5 failed attempts and lasts for 30 seconds.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToVendorError() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_VENDOR
            )
        }
        manager.getCredentials(callback)
        // Should fail because of vendor error
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because of a vendor-specific error.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToPermanentLockout() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT_PERMANENT
            )
        }
        manager.getCredentials(callback)
        // Should fail because of permanent lockout
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the user has been permanently locked out.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToCancellationByUser() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_USER_CANCELED
            )
        }
        manager.getCredentials(callback)
        // Should fail because of cancellation by user
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the user canceled the operation.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToNoBiometrics() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NO_BIOMETRICS
            )
        }
        manager.getCredentials(callback)
        // Should fail because of no biometrics
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the user does not have any biometrics enrolled.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedDueToHardwareNotPresent() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_HW_NOT_PRESENT
            )
        }
        manager.getCredentials(callback)
        // Should fail because hardware is not present
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the device does not have the required authentication hardware.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedBecauseUserPressedTheNegativeButton() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NEGATIVE_BUTTON
            )
        }
        manager.getCredentials(callback)
        // Should fail because user pressed the negative button
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate as the user pressed the negative button.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenBiometricsFailedBecauseNoDeviceCredentials() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL
            )
        }
        manager.getCredentials(callback)
        // Should fail because no device credentials
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Failed to authenticate because the device does not have pin, pattern, or password setup.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsWhenFragmentActivityIsGarbageCollected() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt, "scope")
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)
        manager.clearFragmentActivity()
        manager.getCredentials(callback)
        // Should fail because no fragment activity
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Cannot authenticate as the activity passed is null.")
        )
    }

    /*
     * Custom Clock
     */
    @Test
    public fun shouldUseCustomClock() {
        val manager = SecureCredentialsManager(
            client,
            storage,
            crypto,
            jwtDecoder,
            auth0.executor,
            weakFragmentActivity,
            getAuthenticationOptions(),
            factory
        )
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_access_token_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))

        //now, update the clock and retry
        manager.setClock(object : Clock {
            override fun getCurrentTimeMillis(): Long {
                return CredentialsMock.CURRENT_TIME_MS - 1000
            }
        })
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    @Test(expected = java.lang.IllegalArgumentException::class)
    public fun shouldUseCustomExecutorForGetCredentials() {
        val serialExecutor = object : ExecutorService {
            override fun execute(command: Runnable?) {
                throw IllegalArgumentException("Proper Executor Set")
            }

            override fun shutdown() {}
            override fun shutdownNow(): List<Runnable> = emptyList()
            override fun isShutdown(): Boolean = false
            override fun isTerminated(): Boolean = false
            override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = false
            override fun <T : Any?> submit(task: java.util.concurrent.Callable<T>): java.util.concurrent.Future<T> {
                throw IllegalArgumentException("Proper Executor Set")
            }

            override fun <T : Any?> submit(
                task: Runnable?,
                result: T
            ): java.util.concurrent.Future<T> {
                throw IllegalArgumentException("Proper Executor Set")
            }

            override fun submit(task: Runnable?): java.util.concurrent.Future<*> {
                throw IllegalArgumentException("Proper Executor Set")
            }

            override fun <T : Any?> invokeAll(tasks: Collection<java.util.concurrent.Callable<T>>?): List<java.util.concurrent.Future<T>> {
                throw IllegalArgumentException("Proper Executor Set")
            }

            override fun <T : Any?> invokeAll(
                tasks: Collection<java.util.concurrent.Callable<T>>?,
                timeout: Long,
                unit: TimeUnit
            ): List<java.util.concurrent.Future<T>> {
                throw IllegalArgumentException("Proper Executor Set")
            }

            override fun <T : Any?> invokeAny(tasks: Collection<java.util.concurrent.Callable<T>>?): T {
                throw IllegalArgumentException("Proper Executor Set")
            }

            override fun <T : Any?> invokeAny(
                tasks: Collection<java.util.concurrent.Callable<T>>?,
                timeout: Long,
                unit: TimeUnit
            ): T {
                throw IllegalArgumentException("Proper Executor Set")
            }
        }
        Mockito.`when`(auth0.executor).thenReturn(serialExecutor)
        val manager = SecureCredentialsManager(
            client,
            storage,
            crypto,
            jwtDecoder,
            auth0.executor,
            weakFragmentActivity,
            getAuthenticationOptions(),
            factory
        )
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        manager.continueGetCredentials(
            null,
            0,
            emptyMap(),
            emptyMap(),
            false,
            object : Callback<Credentials, CredentialsManagerException> {
                override fun onSuccess(result: Credentials) {}
                override fun onFailure(error: CredentialsManagerException) {}
            })
    }

    @Test
    public fun shouldAddParametersToRequest() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(
            hasIdToken = false,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        ) // "scope" is set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        val parameters = mapOf(
            "client_id" to "new Client ID",
            "phone" to "+1 (777) 124-1588"
        )
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.continueGetCredentials(
            "some changed scope to trigger refresh",
            0,
            parameters,
            emptyMap(),
            false,
            callback
        )

        verify(request).addParameters(parameters)
        verify(request).execute()
    }

    @Test
    public fun shouldReturnNewCredentialsIfForced() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(
            hasIdToken = false,
            hasAccessToken = true,
            hasRefreshToken = true,
            willExpireAt = expiresAt,
            scope = "scope"
        ) // "scope" is set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        val parameters = mapOf(
            "client_id" to "new Client ID",
            "phone" to "+1 (777) 124-1588"
        )
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "newRefresh", newDate, "oldscope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.continueGetCredentials(
            scope = "scope",
            minTtl = 0,
            parameters = parameters,
            headers = emptyMap(),
            forceRefresh = true,
            callback = callback
        )
        verify(request).execute()
        verify(callback).onSuccess(credentialsCaptor.capture())
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            retrievedCredentials.accessToken,
            Is.`is`(expectedCredentials.accessToken)
        )
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`(expectedCredentials.idToken))
        MatcherAssert.assertThat(
            retrievedCredentials.refreshToken,
            Is.`is`(expectedCredentials.refreshToken)
        )
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`(expectedCredentials.type))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            retrievedCredentials.expiresAt.time,
            Is.`is`(expectedCredentials.expiresAt.time)
        )
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`(expectedCredentials.scope))
    }

    @Test
    public fun shouldReturnSameCredentialsIfNotForced() {
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, true, true, expiresAt, "scope")
        manager.continueGetCredentials(
            "scope",
            0,
            emptyMap(),
            emptyMap(),
            false,
            callback
        )
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    /*
     * Helper methods
     */
    /**
     * Used to simplify the tests length
     */
    private fun insertTestCredentials(
        hasIdToken: Boolean,
        hasAccessToken: Boolean,
        hasRefreshToken: Boolean,
        willExpireAt: Date,
        scope: String?
    ): String {
        val storedCredentials = Credentials(
            if (hasIdToken) "idToken" else "",
            if (hasAccessToken) "accessToken" else "",
            "type",
            if (hasRefreshToken) "refreshToken" else null,
            willExpireAt,
            scope
        )
        val storedJson = gson.toJson(storedCredentials)
        val encoded = String(Base64.encode(storedJson.toByteArray(), Base64.DEFAULT))
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenReturn(storedJson.toByteArray())
        Mockito.`when`(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded)
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(
            willExpireAt.time
        )
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(hasRefreshToken)
        return storedJson
    }


    private fun insertTestApiCredentials(
        audience: String,
        hasAccessToken: Boolean,
        willExpireAt: Date,
        scope: String
    ): String {
        val storedCredentials = ApiCredentialsMock.create(
            if (hasAccessToken) "accessToken" else "",
            "type",
            willExpireAt,
            scope
        )
        val storedJson = gson.toJson(storedCredentials)
        val encoded = String(Base64.encode(storedJson.toByteArray(), Base64.DEFAULT))
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenReturn(storedJson.toByteArray())
        Mockito.`when`(storage.retrieveString(audience)).thenReturn(encoded)
        return storedJson
    }


    private fun prepareJwtDecoderMock(expiresAt: Date?) {
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(expiresAt)
        Mockito.`when`(jwtDecoder.decode("idToken")).thenReturn(jwtMock)
    }

    private companion object {
        private const val ONE_HOUR_SECONDS = (60 * 60).toLong()
        private const val KEY_ALIAS = "com.auth0.key"
    }

    private fun getAuthenticationOptions(
        title: String = "title",
        description: String = "description",
        subtitle: String = "subtitle",
        negativeButtonText: String = "negativeButtonText",
        authenticator: AuthenticationLevel = AuthenticationLevel.STRONG,
        enableDeviceCredentialFallback: Boolean = false
    ): LocalAuthenticationOptions {

        val builder = LocalAuthenticationOptions.Builder()
        builder.apply {
            setTitle(title)
            setSubTitle(subtitle)
            setDescription(description)
            setNegativeButtonText(negativeButtonText)
            setAuthenticationLevel(authenticator)
            setDeviceCredentialFallback(enableDeviceCredentialFallback)
        }
        return builder.build()
    }
}