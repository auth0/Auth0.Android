package com.auth0.android.authentication.storage

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.util.Base64
import androidx.fragment.app.FragmentActivity
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.Jwt
import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.auth0.android.util.Clock
import com.google.gson.Gson
import com.nhaarman.mockitokotlin2.*
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.eq
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.hamcrest.core.IsInstanceOf
import org.junit.Assert
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.*
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import java.lang.reflect.Modifier
import java.util.*
import java.util.concurrent.Executor
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import java.lang.Exception

@RunWith(RobolectricTestRunner::class)
public class SecureCredentialsManagerTest {
    @Mock
    private lateinit var client: AuthenticationAPIClient

    @Mock
    private lateinit var storage: Storage

    @Mock
    private lateinit var callback: Callback<Credentials, CredentialsManagerException>

    @Mock
    private lateinit var request: Request<Credentials, AuthenticationException>

    @Mock
    private lateinit var crypto: CryptoUtil

    @Mock
    private lateinit var jwtDecoder: JWTDecoder

    @Mock
    private lateinit var factory: LocalAuthenticationManagerFactory

    @Mock
    private lateinit var localAuthenticationManager: LocalAuthenticationManager

    private lateinit var fragmentActivity: FragmentActivity

    private val serialExecutor = Executor { runnable -> runnable.run() }

    private val credentialsCaptor: KArgumentCaptor<Credentials> = argumentCaptor()

    private val exceptionCaptor: KArgumentCaptor<CredentialsManagerException> = argumentCaptor()

    private val stringCaptor: KArgumentCaptor<String> = argumentCaptor()

    @get:Rule
    public val exception: ExpectedException = ExpectedException.none()
    private lateinit var manager: SecureCredentialsManager
    private lateinit var gson: Gson

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
        val secureCredentialsManager =
            SecureCredentialsManager(client, storage, crypto, jwtDecoder, serialExecutor, factory)
        manager = Mockito.spy(secureCredentialsManager)
        Mockito.doReturn(CredentialsMock.CURRENT_TIME_MS).`when`(manager).currentTimeInMillis
        gson = GsonProvider.gson
    }

    @Test
    public fun shouldCreateAManagerInstance() {
        val context: Context =
            Robolectric.buildActivity(Activity::class.java).create().start().resume().get()
        val apiClient = AuthenticationAPIClient(Auth0("clientId", "domain"))
        val storage: Storage = SharedPreferencesStorage(context)
        val manager = SecureCredentialsManager(context, apiClient, storage)
        MatcherAssert.assertThat(manager, Is.`is`(Matchers.notNullValue()))
    }

    /*
     * SAVE Credentials tests
     */
    @Test
    public fun shouldSaveRefreshableCredentialsInStorage() {
        val sharedExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials = CredentialsMock(
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
        val credentials: Credentials = CredentialsMock(
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
        val credentials: Credentials = CredentialsMock(
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
            CredentialsMock("idToken", "accessToken", "type", null, Date(expirationTime), "scope")
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
        val credentials: Credentials = CredentialsMock(
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
        val credentials: Credentials = CredentialsMock(
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
            CredentialsMock("", "", "type", "refreshToken", Date(), "scope")
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSaveIfCredentialsHaveAccessTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock("", "accessToken", "type", "refreshToken", Date(), "scope")
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(byteArrayOf(12, 34, 56, 78))
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSaveIfCredentialsHaveIdTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock("idToken", "", "type", "refreshToken", Date(), "scope")
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
        manager.getCredentials(null, 0, emptyMap(), emptyMap(), false, callback)
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
        manager.getCredentials(null, 0, emptyMap(), emptyMap(), false, callback)
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
        manager.getCredentials("different scope", 0, emptyMap(), emptyMap(), false, callback) // minTTL of 0 seconds (default)
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
        manager.getCredentials("different scope", 0, emptyMap(), emptyMap(), false, callback) // minTTL of 0 seconds (default)
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

        manager.getCredentials("different scope", 0, emptyMap(), emptyMap(), false, callback) // minTTL of 0 seconds (default)
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
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(false, false, true, expiresAt, "scope")
        manager.getCredentials(null, 0, emptyMap(), emptyMap(), false, callback)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.message, Is.`is`("No Credentials were previously set."))
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenExpiredAndNoRefreshTokenWasSaved() {
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) //Same as current time --> expired
        insertTestCredentials(true, true, false, expiresAt, "scope")
        manager.getCredentials(null, 0, emptyMap(), emptyMap(), false, callback)
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
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, true, true, expiresAt, "scope")
        manager.getCredentials(null, 0, emptyMap(), emptyMap(), false, callback)
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
        val retrievedCredentials = manager.awaitCredentials(fragmentActivity, getAuthenticationOptions())
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
            runBlocking { manager.awaitCredentials(fragmentActivity, getAuthenticationOptions()) }
        }
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Credentials need to be renewed but no Refresh Token is available to renew them.")
        )
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() {
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, false, true, expiresAt, "scope")
        manager.getCredentials(null, 0, emptyMap(), emptyMap(), false, callback)
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
        verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        manager.getCredentials(
            null,
            0,
            emptyMap(),
            emptyMap(),
            false,
            callback)
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
        manager.getCredentials(null, 60, emptyMap(), emptyMap(), false, callback) // minTTL of 1 minute
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
        manager.getCredentials(null, 60, emptyMap(), emptyMap(), false, callback) // minTTL of 1 minute
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
        manager.getCredentials("different scope", 0, emptyMap(), emptyMap(), false, callback) // minTTL of 0 seconds (default)
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
        manager.getCredentials("different scope", 0, emptyMap(), emptyMap(), false, callback) // minTTL of 0 seconds (default)
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
        manager.getCredentials("different scope", 0, emptyMap(), emptyMap(), false, callback) // minTTL of 0 seconds (default)
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
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", null, newDate, "newScope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        manager.getCredentials(
            null,
            0,
            emptyMap(),
            emptyMap(),
            false,
            callback)
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
        manager.getCredentials(
            null,
            0,
            emptyMap(),
            emptyMap(),
            false,
            callback)
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
    public fun shouldGetAndFailToRenewExpiredCredentials() {
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt, "scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        //Trigger failure
        val authenticationException = mock<AuthenticationException>()
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
        manager.getCredentials(
            null,
            0,
            emptyMap(),
            emptyMap(),
            false,
            callback)
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

        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_HW_UNAVAILABLE
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_UNABLE_TO_PROCESS
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_TIMEOUT
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NO_SPACE
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_CANCELED
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_VENDOR
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_LOCKOUT_PERMANENT
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_USER_CANCELED
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NO_BIOMETRICS
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_HW_NOT_PRESENT
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NEGATIVE_BUTTON
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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
        Mockito.`when`(localAuthenticationManager.authenticate()).then {
            localAuthenticationManager.resultCallback.onFailure(
                CredentialsManagerException.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL
            )
        }
        manager.getCredentials(
            fragmentActivity,
            getAuthenticationOptions(),
            callback
        )
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

    /*
     * Custom Clock
     */
    @Test
    public fun shouldUseCustomClock() {
        val manager = SecureCredentialsManager(client, storage, crypto, jwtDecoder, serialExecutor, factory) { }
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
        val manager = SecureCredentialsManager(apiClient = client, storage = storage, crypto = crypto, jwtDecoder = jwtDecoder) {
            throw java.lang.IllegalArgumentException("Proper Executor Set")
        }
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        manager.getCredentials(object : Callback<Credentials, CredentialsManagerException> {
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
        manager.getCredentials(
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
        manager.getCredentials(
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
        manager.getCredentials(
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

    @Test
    public fun shouldBeMarkedSynchronous() {
        val method =
            SecureCredentialsManager::class.java.getMethod(
                "saveCredentials",
                Credentials::class.java
            )
        assertTrue(Modifier.isSynchronized(method.modifiers))
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
            title(title)
            subtitle(subtitle)
            description(description)
            negativeButtonText(negativeButtonText)
            authenticator(authenticator)
            enableDeviceCredentialFallback(enableDeviceCredentialFallback)
        }
        return builder.build()
    }
}