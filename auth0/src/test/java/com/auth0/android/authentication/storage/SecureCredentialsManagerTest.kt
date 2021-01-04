package com.auth0.android.authentication.storage

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build.VERSION
import android.util.Base64
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.BaseCallback
import com.auth0.android.jwt.JWT
import com.auth0.android.request.Request
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.google.gson.Gson
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.eq
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
import org.mockito.*
import org.mockito.ArgumentMatchers.*
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import java.util.*

@RunWith(RobolectricTestRunner::class)
public class SecureCredentialsManagerTest {
    @Mock
    private lateinit var client: AuthenticationAPIClient

    @Mock
    private lateinit var storage: Storage

    @Mock
    private lateinit var callback: BaseCallback<Credentials, CredentialsManagerException>

    @Mock
    private lateinit var request: Request<Credentials, AuthenticationException>

    @Mock
    private lateinit var crypto: CryptoUtil

    @Mock
    private lateinit var jwtDecoder: JWTDecoder

    @Captor
    private lateinit var credentialsCaptor: ArgumentCaptor<Credentials>

    @Captor
    private lateinit var exceptionCaptor: ArgumentCaptor<CredentialsManagerException>

    @Captor
    private lateinit var stringCaptor: ArgumentCaptor<String>

    @Captor
    private lateinit var requestCallbackCaptor: ArgumentCaptor<BaseCallback<Credentials, AuthenticationException>>

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
        val kManager = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activityContext.getSystemService(Context.KEYGUARD_SERVICE))
            .thenReturn(kManager)
        val secureCredentialsManager =
            SecureCredentialsManager(client, storage, crypto, jwtDecoder)
        manager = Mockito.spy(secureCredentialsManager)
        Mockito.doReturn(CredentialsMock.CURRENT_TIME_MS).`when`(manager).currentTimeInMillis
        gson = GsonProvider.buildGson()
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
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", sharedExpirationTime)
        Mockito.verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", sharedExpirationTime)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage).store("com.auth0.manager_key_alias", KEY_ALIAS)
        Mockito.verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.value
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(storedCredentials.expiresAt!!.time, Is.`is`(sharedExpirationTime))
        MatcherAssert.assertThat(storedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldSaveRefreshableCredentialsUsingAccessTokenExpForCacheExpirationInStorage() {
        val accessTokenExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials = CredentialsMock(
            null,
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
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", accessTokenExpirationTime)
        Mockito.verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", accessTokenExpirationTime)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage).store("com.auth0.manager_key_alias", KEY_ALIAS)
        Mockito.verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.value
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            storedCredentials.expiresAt!!.time,
            Is.`is`(accessTokenExpirationTime)
        )
        MatcherAssert.assertThat(storedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldSaveRefreshableCredentialsUsingIdTokenExpForCacheExpirationInStorage() {
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
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", idTokenExpirationTime)
        Mockito.verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", accessTokenExpirationTime)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage).store("com.auth0.manager_key_alias", KEY_ALIAS)
        Mockito.verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.value
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            storedCredentials.expiresAt!!.time,
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
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", expirationTime)
        Mockito.verify(storage)
            .store("com.auth0.credentials_access_token_expires_at", expirationTime)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", false)
        Mockito.verify(storage).store("com.auth0.manager_key_alias", KEY_ALIAS)
        Mockito.verifyNoMoreInteractions(storage)
        val encodedJson = stringCaptor.value
        MatcherAssert.assertThat(encodedJson, Is.`is`(Matchers.notNullValue()))
        val decoded = Base64.decode(encodedJson, Base64.DEFAULT)
        val storedCredentials = gson.fromJson(String(decoded), Credentials::class.java)
        MatcherAssert.assertThat(storedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(storedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(storedCredentials.refreshToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(storedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(storedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(storedCredentials.expiresAt!!.time, Is.`is`(expirationTime))
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
            Is.`is`("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Please, try saving the credentials again.")
        )
        Mockito.verify(storage).remove("com.auth0.credentials")
        Mockito.verify(storage).remove("com.auth0.credentials_expires_at")
        Mockito.verify(storage).remove("com.auth0.credentials_can_refresh")
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
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.")
        val credentials: Credentials =
            CredentialsMock(null, null, "type", "refreshToken", ONE_HOUR_SECONDS)
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldThrowOnSaveIfCredentialsDoesNotHaveExpiresAt() {
        exception.expect(CredentialsManagerException::class.java)
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.")
        val date: Date? = null
        val credentials: Credentials =
            CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope")
        prepareJwtDecoderMock(Date())
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSaveIfCredentialsHaveAccessTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock(null, "accessToken", "type", "refreshToken", ONE_HOUR_SECONDS)
        Mockito.`when`(crypto.encrypt(any()))
            .thenReturn(byteArrayOf(12, 34, 56, 78))
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSaveIfCredentialsHaveIdTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock("idToken", null, "type", "refreshToken", ONE_HOUR_SECONDS)
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
        Mockito.verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedJson = insertTestCredentials(true, true, true, expiresAt)
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenThrow(CryptoException("err", null))
        manager.getCredentials(callback)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.value
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.cause, IsInstanceOf.instanceOf(
                CryptoException::class.java
            )
        )
        MatcherAssert.assertThat(
            exception.message, Is.`is`(
                "A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. " +
                        "Any previously stored content is now lost. Please, try saving the credentials again."
            )
        )
        Mockito.verify(storage).remove("com.auth0.credentials")
        Mockito.verify(storage).remove("com.auth0.credentials_expires_at")
        Mockito.verify(storage).remove("com.auth0.credentials_can_refresh")
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenIncompatibleDeviceExceptionIsThrown() {
        Mockito.verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedJson = insertTestCredentials(true, true, true, expiresAt)
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenThrow(IncompatibleDeviceException(null))
        manager.getCredentials(callback)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.value
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
        Mockito.verify(storage, Mockito.never()).remove("com.auth0.credentials")
        Mockito.verify(storage, Mockito.never()).remove("com.auth0.credentials_expires_at")
        Mockito.verify(storage, Mockito.never()).remove("com.auth0.credentials_can_refresh")
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenNoAccessTokenOrIdTokenWasSaved() {
        Mockito.verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(false, false, true, expiresAt)
        manager.getCredentials(callback)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.value
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.message, Is.`is`("No Credentials were previously set."))
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenExpiredAndNoRefreshTokenWasSaved() {
        Mockito.verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) //Same as current time --> expired
        insertTestCredentials(true, true, false, expiresAt)
        manager.getCredentials(callback)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.value
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.message, Is.`is`("No Credentials were previously set."))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorage() {
        Mockito.verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, true, true, expiresAt)
        manager.getCredentials(callback)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt!!.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() {
        Mockito.verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, false, true, expiresAt)
        manager.getCredentials(callback)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt!!.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorageWhenOnlyAccessTokenIsAvailable() {
        Mockito.verifyNoMoreInteractions(client)
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(false, true, true, expiresAt)
        manager.getCredentials(callback)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt!!.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldRenewCredentialsWithMinTtl() {
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) // expired credentials
        insertTestCredentials(false, true, true, expiresAt)
        val newDate =
            Date(CredentialsMock.CURRENT_TIME_MS + 61 * 1000) // new token expires in minTTL + 1 seconds
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials(null, 60, callback) // minTTL of 1 minute
        Mockito.verify(request, Mockito.never())
            .addParameter(eq("scope"), anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        requestCallbackCaptor.value.onSuccess(expectedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage, Mockito.never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.value
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
            renewedStoredCredentials.expiresAt!!.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenReceivedTokenHasLowerTtl() {
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS) // expired credentials
        insertTestCredentials(false, true, true, expiresAt)
        val newDate =
            Date(CredentialsMock.CURRENT_TIME_MS + 59 * 1000) // new token expires in minTTL - 1 seconds
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials(null, 60, callback) // minTTL of 1 minute
        Mockito.verify(request, Mockito.never())
            .addParameter(eq("scope"), anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger failure
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        requestCallbackCaptor.value.onSuccess(expectedCredentials)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.value
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("The lifetime of the renewed Access Token (1) is less than the minTTL requested (60). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.")
        )
        Mockito.verify(storage, Mockito.never())
            .store(eq("com.auth0.credentials"), anyString())
        Mockito.verify(storage, Mockito.never()).store(
            eq("com.auth0.credentials_expires_at"),
            anyLong()
        )
        Mockito.verify(storage, Mockito.never()).store(
            eq("com.auth0.credentials_can_refresh"),
            anyBoolean()
        )
        Mockito.verify(storage, Mockito.never()).remove(anyString())
    }

    @Test
    public fun shouldRenewCredentialsWhenScopeHasChanged() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS) // non expired credentials
        insertTestCredentials(false, true, true, expiresAt) // "scope" is set
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials("different scope", 0, callback) // minTTL of 0 seconds (default)
        Mockito.verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        requestCallbackCaptor.value.onSuccess(expectedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage, Mockito.never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("different scope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.value
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
            renewedStoredCredentials.expiresAt!!.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("different scope"))
    }

    @Test
    public fun shouldRenewExpiredCredentialsWhenScopeHasChanged() {
        val expiresAt =
            Date(CredentialsMock.CURRENT_TIME_MS) // current time means expired credentials
        insertTestCredentials(false, true, true, expiresAt)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials("different scope", 0, callback) // minTTL of 0 seconds (default)
        Mockito.verify(request)
            .addParameter(eq("scope"), eq("different scope"))
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger success
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        requestCallbackCaptor.value.onSuccess(expectedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage, Mockito.never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("different scope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.value
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
            renewedStoredCredentials.expiresAt!!.time, Is.`is`(newDate.time)
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
        insertTestCredentials(false, true, true, expiresAt)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials(callback)
        Mockito.verify(request, Mockito.never())
            .addParameter(eq("scope"), anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", null, newDate, "newScope")
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope")
        val expectedJson = gson.toJson(expectedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage, Mockito.never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.value
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
            renewedStoredCredentials.expiresAt!!.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndSuccessfullyRenewExpiredCredentialsWithRefreshTokenRotation() {
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials(callback)
        Mockito.verify(request, Mockito.never())
            .addParameter(eq("scope"), anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        //Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope")
        val expectedJson = gson.toJson(renewedCredentials)
        Mockito.`when`(crypto.encrypt(expectedJson.toByteArray()))
            .thenReturn(expectedJson.toByteArray())
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        Mockito.verify(storage)
            .store(eq("com.auth0.credentials"), stringCaptor.capture())
        Mockito.verify(storage).store("com.auth0.credentials_expires_at", newDate.time)
        Mockito.verify(storage).store("com.auth0.credentials_can_refresh", true)
        Mockito.verify(storage, Mockito.never()).remove(anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("rotatedRefreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))

        // Verify the credentials are property stored
        val encodedJson = stringCaptor.value
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
            renewedStoredCredentials.expiresAt!!.time, Is.`is`(newDate.time)
        )
        MatcherAssert.assertThat(renewedStoredCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentials() {
        val expiresAt = Date(CredentialsMock.CURRENT_TIME_MS)
        insertTestCredentials(false, true, true, expiresAt)
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials(callback)
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        //Trigger failure
        val authenticationException = Mockito.mock(
            AuthenticationException::class.java
        )
        requestCallbackCaptor.value.onFailure(authenticationException)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        Mockito.verify(storage, Mockito.never())
            .store(anyString(), anyLong())
        Mockito.verify(storage, Mockito.never())
            .store(anyString(), anyInt())
        Mockito.verify(storage, Mockito.never())
            .store(anyString(), anyString())
        Mockito.verify(storage, Mockito.never())
            .store(anyString(), anyBoolean())
        Mockito.verify(storage, Mockito.never()).remove(anyString())
        val exception = exceptionCaptor.value
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
        Mockito.verify(storage).remove("com.auth0.credentials")
        Mockito.verify(storage).remove("com.auth0.credentials_expires_at")
        Mockito.verify(storage).remove("com.auth0.credentials_access_token_expires_at")
        Mockito.verify(storage).remove("com.auth0.credentials_can_refresh")
        Mockito.verify(storage).remove("com.auth0.manager_key_alias")
        Mockito.verifyNoMoreInteractions(storage)
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
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(KEY_ALIAS)
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
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(KEY_ALIAS)
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
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(KEY_ALIAS)
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
    }

    @Test
    public fun shouldHaveCredentialsWhenTokenHasExpiredButRefreshTokenIsAvailable() {
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(true)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\", \"refresh_token\":\"refreshToken\"}")
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(KEY_ALIAS)
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\", \"refresh_token\":\"refreshToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    @Test
    public fun shouldNotHaveCredentialsWhenAccessTokenAndIdTokenAreMissing() {
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"token_type\":\"type\", \"refresh_token\":\"refreshToken\"}")
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(KEY_ALIAS)
        Assert.assertFalse(manager.hasValidCredentials())
    }

    @Test
    public fun shouldNotHaveCredentialsWhenTheAliasUsedHasNotBeenMigratedYet() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias"))
            .thenReturn("old_alias")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
    }

    @Test
    public fun shouldNotHaveCredentialsWhenTheAliasUsedHasNotBeenSetYet() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"id_token\":\"idToken\"}")
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(null)
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))
    }

    /*
     * Authentication tests
     */
    @Test
    public fun shouldThrowOnInvalidAuthenticationRequestCode() {
        exception.expect(IllegalArgumentException::class.java)
        exception.expectMessage("Request code must be a value between 1 and 255.")
        val activity =
            Robolectric.buildActivity(Activity::class.java).create().start().resume().get()
        manager.requireAuthentication(activity, 256, null, null)
    }

    @Test
    @Config(sdk = [21])
    public fun shouldNotRequireAuthenticationIfAPI21AndLockScreenDisabled() {
        ReflectionHelpers.setStaticField(VERSION::class.java, "SDK_INT", 21)
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )

        //Set LockScreen as Disabled
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isKeyguardSecure).thenReturn(false)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("title", "description"))
            .thenReturn(null)
        val willAskAuthentication =
            manager.requireAuthentication(activity, 123, "title", "description")
        MatcherAssert.assertThat(willAskAuthentication, Is.`is`(false))
    }

    @Test
    @Config(sdk = [23])
    public fun shouldNotRequireAuthenticationIfAPI23AndLockScreenDisabled() {
        ReflectionHelpers.setStaticField(VERSION::class.java, "SDK_INT", 23)
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )

        //Set LockScreen as Disabled
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isDeviceSecure).thenReturn(false)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("title", "description"))
            .thenReturn(null)
        val willAskAuthentication =
            manager.requireAuthentication(activity, 123, "title", "description")
        MatcherAssert.assertThat(willAskAuthentication, Is.`is`(false))
    }

    @Test
    @Config(sdk = [21])
    public fun shouldRequireAuthenticationIfAPI21AndLockScreenEnabled() {
        ReflectionHelpers.setStaticField(VERSION::class.java, "SDK_INT", 21)
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )

        //Set LockScreen as Enabled
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isKeyguardSecure).thenReturn(true)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("title", "description"))
            .thenReturn(Intent())
        val willAskAuthentication =
            manager.requireAuthentication(activity, 123, "title", "description")
        MatcherAssert.assertThat(willAskAuthentication, Is.`is`(true))
    }

    @Test
    @Config(sdk = [23])
    public fun shouldRequireAuthenticationIfAPI23AndLockScreenEnabled() {
        ReflectionHelpers.setStaticField(VERSION::class.java, "SDK_INT", 23)
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )

        //Set LockScreen as Enabled
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isDeviceSecure).thenReturn(true)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("title", "description"))
            .thenReturn(Intent())
        val willAskAuthentication =
            manager.requireAuthentication(activity, 123, "title", "description")
        MatcherAssert.assertThat(willAskAuthentication, Is.`is`(true))
    }

    @Test
    public fun shouldGetCredentialsAfterAuthentication() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt)
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expiresAt.time)

        //Require authentication
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isKeyguardSecure).thenReturn(true)
        val confirmCredentialsIntent = Mockito.mock(Intent::class.java)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription"))
            .thenReturn(confirmCredentialsIntent)
        val willRequireAuthentication =
            manager.requireAuthentication(activity, 123, "theTitle", "theDescription")
        MatcherAssert.assertThat(willRequireAuthentication, Is.`is`(true))
        manager.getCredentials(callback)
        val intentCaptor = ArgumentCaptor.forClass(Intent::class.java)
        Mockito.verify(activity)
            .startActivityForResult(intentCaptor.capture(), eq(123))
        MatcherAssert.assertThat(intentCaptor.value, Is.`is`(confirmCredentialsIntent))


        //Continue after successful authentication
        val processed = manager.checkAuthenticationResult(123, Activity.RESULT_OK)
        MatcherAssert.assertThat(processed, Is.`is`(true))
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt!!.time, Is.`is`(expiresAt.time))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))

        //A second call to checkAuthenticationResult should fail as callback is set to null
        val retryCheck = manager.checkAuthenticationResult(123, Activity.RESULT_OK)
        MatcherAssert.assertThat(retryCheck, Is.`is`(false))
    }

    @Test
    public fun shouldNotGetCredentialsWhenCredentialsHaveExpired() {
        val credentialsExpiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val storedExpiresAt = Date(CredentialsMock.CURRENT_TIME_MS - ONE_HOUR_SECONDS * 1000)
        insertTestCredentials(true, true, false, credentialsExpiresAt)
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(storedExpiresAt.time)

        //Require authentication
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isKeyguardSecure).thenReturn(true)
        val confirmCredentialsIntent = Mockito.mock(Intent::class.java)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription"))
            .thenReturn(confirmCredentialsIntent)
        val willRequireAuthentication =
            manager.requireAuthentication(activity, 123, "theTitle", "theDescription")
        MatcherAssert.assertThat(willRequireAuthentication, Is.`is`(true))
        manager.getCredentials(callback)

        //Should fail because of expired credentials
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.value
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.message, Is.`is`("No Credentials were previously set."))

        //A second call to checkAuthenticationResult should fail as callback is set to null
        val retryCheck = manager.checkAuthenticationResult(123, Activity.RESULT_OK)
        MatcherAssert.assertThat(retryCheck, Is.`is`(false))
    }

    @Test
    public fun shouldNotGetCredentialsAfterCanceledAuthentication() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt)

        //Require authentication
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isKeyguardSecure).thenReturn(true)
        val confirmCredentialsIntent = Mockito.mock(Intent::class.java)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription"))
            .thenReturn(confirmCredentialsIntent)
        val willRequireAuthentication =
            manager.requireAuthentication(activity, 123, "theTitle", "theDescription")
        MatcherAssert.assertThat(willRequireAuthentication, Is.`is`(true))
        manager.getCredentials(callback)
        val intentCaptor = ArgumentCaptor.forClass(Intent::class.java)
        Mockito.verify(activity)
            .startActivityForResult(intentCaptor.capture(), eq(123))
        MatcherAssert.assertThat(intentCaptor.value, Is.`is`(confirmCredentialsIntent))


        //Continue after canceled authentication
        val processed = manager.checkAuthenticationResult(123, Activity.RESULT_CANCELED)
        MatcherAssert.assertThat(processed, Is.`is`(true))
        Mockito.verify(callback, Mockito.never()).onSuccess(any())
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        MatcherAssert.assertThat(exceptionCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exceptionCaptor.value.message,
            Is.`is`("The user didn't pass the authentication challenge.")
        )
    }

    @Test
    public fun shouldNotGetCredentialsOnDifferentAuthenticationRequestCode() {
        val expiresAt = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        insertTestCredentials(true, true, false, expiresAt)

        //Require authentication
        val activity = Mockito.spy(
            Robolectric.buildActivity(
                Activity::class.java
            ).create().start().resume().get()
        )
        val kService = Mockito.mock(KeyguardManager::class.java)
        Mockito.`when`(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService)
        Mockito.`when`(kService.isKeyguardSecure).thenReturn(true)
        val confirmCredentialsIntent = Mockito.mock(Intent::class.java)
        Mockito.`when`(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription"))
            .thenReturn(confirmCredentialsIntent)
        val willRequireAuthentication =
            manager.requireAuthentication(activity, 100, "theTitle", "theDescription")
        MatcherAssert.assertThat(willRequireAuthentication, Is.`is`(true))
        manager.getCredentials(callback)
        val intentCaptor = ArgumentCaptor.forClass(Intent::class.java)
        Mockito.verify(activity)
            .startActivityForResult(intentCaptor.capture(), eq(100))
        MatcherAssert.assertThat(intentCaptor.value, Is.`is`(confirmCredentialsIntent))


        //Continue after successful authentication
        Mockito.verifyNoMoreInteractions(callback)
        val processed = manager.checkAuthenticationResult(123, Activity.RESULT_OK)
        MatcherAssert.assertThat(processed, Is.`is`(false))
    }

    /*
     * Custom Clock
     */
    @Test
    public fun shouldUseCustomClock() {
        val manager = SecureCredentialsManager(client, storage, crypto, jwtDecoder)
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(false)
        Mockito.`when`(storage.retrieveString("com.auth0.credentials"))
            .thenReturn("{\"access_token\":\"accessToken\"}")
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(KEY_ALIAS)
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))

        //now, update the clock and retry
        manager.setClock { CredentialsMock.CURRENT_TIME_MS - 1000 }
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
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
        willExpireAt: Date?
    ): String {
        val storedCredentials = Credentials(
            if (hasIdToken) "idToken" else null,
            if (hasAccessToken) "accessToken" else null,
            "type",
            if (hasRefreshToken) "refreshToken" else null,
            willExpireAt,
            "scope"
        )
        val storedJson = gson.toJson(storedCredentials)
        val encoded = String(Base64.encode(storedJson.toByteArray(), Base64.DEFAULT))
        Mockito.`when`(crypto.decrypt(storedJson.toByteArray()))
            .thenReturn(storedJson.toByteArray())
        Mockito.`when`(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded)
        Mockito.`when`(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(
            willExpireAt?.time
        )
        Mockito.`when`(storage.retrieveBoolean("com.auth0.credentials_can_refresh"))
            .thenReturn(hasRefreshToken)
        Mockito.`when`(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(KEY_ALIAS)
        return storedJson
    }

    private fun prepareJwtDecoderMock(expiresAt: Date?) {
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(expiresAt)
        Mockito.`when`(jwtDecoder.decode("idToken")).thenReturn(jwtMock)
    }

    private companion object {
        private const val ONE_HOUR_SECONDS = (60 * 60).toLong()
        private const val KEY_ALIAS = "com.auth0.key"
    }
}