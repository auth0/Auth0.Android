package com.auth0.android.authentication.storage

import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.BaseCallback
import com.auth0.android.jwt.JWT
import com.auth0.android.request.Request
import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.auth0.android.util.Clock
import com.nhaarman.mockitokotlin2.*
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.Assert
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.robolectric.RobolectricTestRunner
import java.util.*

@RunWith(RobolectricTestRunner::class)
public class CredentialsManagerTest {
    @Mock
    private lateinit var client: AuthenticationAPIClient

    @Mock
    private lateinit var storage: Storage

    @Mock
    private lateinit var callback: BaseCallback<Credentials, CredentialsManagerException>

    @Mock
    private lateinit var request: Request<Credentials, AuthenticationException>

    @Mock
    private lateinit var jwtDecoder: JWTDecoder

    private val credentialsCaptor: KArgumentCaptor<Credentials> = argumentCaptor()

    private val exceptionCaptor: KArgumentCaptor<CredentialsManagerException> = argumentCaptor()

    @get:Rule
    public var exception: ExpectedException = ExpectedException.none()
    private lateinit var manager: CredentialsManager

    private val requestCallbackCaptor: KArgumentCaptor<BaseCallback<Credentials, AuthenticationException>> =
        argumentCaptor()

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        val credentialsManager = CredentialsManager(client, storage, jwtDecoder)
        manager = Mockito.spy(credentialsManager)
        //Needed to test expiration verification
        Mockito.doReturn(CredentialsMock.CURRENT_TIME_MS).`when`(manager).currentTimeInMillis
        Mockito.doAnswer { invocation ->
            val idToken = invocation.getArgument(0, String::class.java)
            val accessToken = invocation.getArgument(1, String::class.java)
            val type = invocation.getArgument(2, String::class.java)
            val refreshToken = invocation.getArgument(3, String::class.java)
            val expiresAt = invocation.getArgument(4, Date::class.java)
            val scope = invocation.getArgument(5, String::class.java)
            CredentialsMock(idToken, accessToken, type, refreshToken, expiresAt, scope)
        }.`when`(manager).recreateCredentials(
            ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString(),
            any(),
            ArgumentMatchers.anyString()
        )
    }

    @Test
    public fun shouldSaveRefreshableCredentialsInStorage() {
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
        manager.saveCredentials(credentials)
        verify(storage).store("com.auth0.id_token", "idToken")
        verify(storage).store("com.auth0.access_token", "accessToken")
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", "type")
        verify(storage).store("com.auth0.expires_at", expirationTime)
        verify(storage).store("com.auth0.scope", "scope")
        verify(storage).store("com.auth0.cache_expires_at", expirationTime)
        verifyNoMoreInteractions(storage)
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
        prepareJwtDecoderMock(Date(accessTokenExpirationTime))
        manager.saveCredentials(credentials)
        verify(storage).store("com.auth0.id_token", null as String?)
        verify(storage).store("com.auth0.access_token", "accessToken")
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", "type")
        verify(storage).store("com.auth0.expires_at", accessTokenExpirationTime)
        verify(storage).store("com.auth0.scope", "scope")
        verify(storage).store("com.auth0.cache_expires_at", accessTokenExpirationTime)
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldSaveRefreshableCredentialsUsingIdTokenExpForCacheExpirationInStorage() {
        val accessTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 5000 * 1000
        val idTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 2000 * 1000
        val credentials: Credentials = CredentialsMock(
            "idToken",
            "accessToken",
            "type",
            "refreshToken",
            Date(accessTokenExpirationTime),
            "scope"
        )
        prepareJwtDecoderMock(Date(idTokenExpirationTime))
        manager.saveCredentials(credentials)
        verify(storage).store("com.auth0.id_token", "idToken")
        verify(storage).store("com.auth0.access_token", "accessToken")
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", "type")
        verify(storage).store("com.auth0.expires_at", accessTokenExpirationTime)
        verify(storage).store("com.auth0.scope", "scope")
        verify(storage).store("com.auth0.cache_expires_at", idTokenExpirationTime)
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldSaveNonRefreshableCredentialsInStorage() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials =
            CredentialsMock("idToken", "accessToken", "type", null, Date(expirationTime), "scope")
        prepareJwtDecoderMock(Date(expirationTime))
        manager.saveCredentials(credentials)
        verify(storage).store("com.auth0.id_token", "idToken")
        verify(storage).store("com.auth0.access_token", "accessToken")
        verify(storage).store("com.auth0.refresh_token", null as String?)
        verify(storage).store("com.auth0.token_type", "type")
        verify(storage).store("com.auth0.expires_at", expirationTime)
        verify(storage).store("com.auth0.scope", "scope")
        verify(storage).store("com.auth0.cache_expires_at", expirationTime)
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldThrowOnSetIfCredentialsDoesNotHaveIdTokenOrAccessToken() {
        exception.expect(CredentialsManagerException::class.java)
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.")
        val credentials: Credentials = CredentialsMock(null, null, "type", "refreshToken", 123456L)
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldThrowOnSetIfCredentialsDoesNotHaveExpiresAt() {
        exception.expect(CredentialsManagerException::class.java)
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.")
        val date: Date? = null
        val credentials: Credentials =
            CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope")
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSetIfCredentialsHaveAccessTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock(null, "accessToken", "type", "refreshToken", 123456L)
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSetIfCredentialsHaveIdTokenAndExpiresIn() {
        val credentials: Credentials =
            CredentialsMock("idToken", null, "type", "refreshToken", 123456L)
        prepareJwtDecoderMock(Date())
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldFailOnGetCredentialsWhenNoAccessTokenOrIdTokenWasSaved() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
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
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
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
    public fun shouldNotFailOnGetCredentialsWhenCacheExpiresAtNotSetButExpiresAtIsPresent() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        manager.getCredentials(callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorage() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
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
        MatcherAssert.assertThat(retrievedCredentials.expiresIn, Is.`is`(Matchers.notNullValue()))
        // TODO [SDK-2184]: fix clock mocking to avoid CredentialsManager expiresIn calculation
        MatcherAssert.assertThat(
            retrievedCredentials.expiresIn!!.toDouble(), CoreMatchers.`is`(
                Matchers.closeTo(ONE_HOUR_SECONDS.toDouble(), 50.0)
            )
        )
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt!!.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        manager.getCredentials(callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresIn, Is.`is`(Matchers.notNullValue()))
        // TODO [SDK-2184]: fix clock mocking to avoid CredentialsManager expiresIn calculation
        MatcherAssert.assertThat(
            retrievedCredentials.expiresIn!!.toDouble(), CoreMatchers.`is`(
                Matchers.closeTo(ONE_HOUR_SECONDS.toDouble(), 50.0)
            )
        )
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt!!.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorageWhenOnlyAccessTokenIsAvailable() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        manager.getCredentials(callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresIn, Is.`is`(Matchers.notNullValue()))
        // TODO [SDK-2184]: fix clock mocking to avoid CredentialsManager expiresIn calculation
        MatcherAssert.assertThat(
            retrievedCredentials.expiresIn!!.toDouble(), CoreMatchers.`is`(
                Matchers.closeTo(ONE_HOUR_SECONDS.toDouble(), 50.0)
            )
        )
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt!!.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldRenewExpiredCredentialsWhenScopeHasChanged() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS // expired credentials
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<JWT>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials("some scope", 0, callback)
        verify(request).start(
            requestCallbackCaptor.capture()
        )
        verify(request)
            .addParameter(eq("scope"), eq("some scope"))

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "some scope")
        requestCallbackCaptor.firstValue.onSuccess(renewedCredentials)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh)
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage, never()).remove(ArgumentMatchers.anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("some scope"))
    }

    @Test
    public fun shouldRenewCredentialsWhenScopeHasChanged() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS // non expired credentials
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("some new scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<JWT>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials("some scope", 0, callback)
        verify(request).start(
            requestCallbackCaptor.capture()
        )
        verify(request)
            .addParameter(eq("scope"), eq("some scope"))

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.firstValue.onSuccess(renewedCredentials)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh)
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage, never()).remove(ArgumentMatchers.anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldRenewCredentialsWithMinTtl() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS // Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        val newDate =
            Date(CredentialsMock.CURRENT_TIME_MS + 61 * 1000) // New token expires in minTTL + 1 second
        val jwtMock = mock<JWT>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(null, 60, callback) // 60 seconds of minTTL
        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())
        verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.firstValue.onSuccess(renewedCredentials)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh)
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage, never()).remove(ArgumentMatchers.anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndSuccessfullyRenewExpiredCredentials() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<JWT>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(callback)
        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())
        verify(request).start(
            requestCallbackCaptor.capture()
        )

        //Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.firstValue.onSuccess(renewedCredentials)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        //RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh)
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage, never()).remove(ArgumentMatchers.anyString())

        //// Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenReceivedTokenHasLowerTtl() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS // Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        val newDate =
            Date(CredentialsMock.CURRENT_TIME_MS + 59 * 1000) // New token expires in minTTL - 1 second
        val jwtMock = mock<JWT>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(null, 60, callback) // 60 seconds of minTTL
        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())
        verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger failure
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.firstValue.onSuccess(renewedCredentials)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )

        // Verify the credentials are never stored
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt())
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong())
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyBoolean())
        verify(storage, never()).remove(ArgumentMatchers.anyString())
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("The lifetime of the renewed Access Token (1) is less than the minTTL requested (60). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.")
        )
    }

    @Test
    public fun shouldGetAndSuccessfullyRenewExpiredCredentialsWithRefreshTokenRotation() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<JWT>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(callback)
        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())
        verify(request).start(
            requestCallbackCaptor.capture()
        )

        //Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope")
        requestCallbackCaptor.firstValue.onSuccess(renewedCredentials)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        //RefreshToken should be replaced
        verify(storage).store("com.auth0.refresh_token", "rotatedRefreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        verify(storage, never()).remove(ArgumentMatchers.anyString())

        //// Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("newId"))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("rotatedRefreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldGetAndFailToRenewExpiredCredentials() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)
        manager.getCredentials(callback)
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt())
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong())
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        verify(storage, never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyBoolean())
        verify(storage, never()).remove(ArgumentMatchers.anyString())
        verify(request).start(
            requestCallbackCaptor.capture()
        )

        //Trigger failure
        val authenticationException = Mockito.mock(
            AuthenticationException::class.java
        )
        requestCallbackCaptor.firstValue.onFailure(authenticationException)
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception.cause, Is.`is`(authenticationException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An error occurred while trying to use the Refresh Token to renew the Credentials.")
        )
    }

    @Test
    public fun shouldClearCredentials() {
        manager.clearCredentials()
        verify(storage).remove("com.auth0.id_token")
        verify(storage).remove("com.auth0.access_token")
        verify(storage).remove("com.auth0.refresh_token")
        verify(storage).remove("com.auth0.token_type")
        verify(storage).remove("com.auth0.expires_at")
        verify(storage).remove("com.auth0.scope")
        verify(storage).remove("com.auth0.cache_expires_at")
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldHaveCredentialsWhenTokenHasNotExpired() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn(null)
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        MatcherAssert.assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        MatcherAssert.assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), Is.`is`(true))
    }

    @Test
    public fun shouldNotHaveCredentialsWhenTokenHasExpiredAndNoRefreshTokenIsAvailable() {
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn(null)
        Assert.assertFalse(manager.hasValidCredentials())
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Assert.assertFalse(manager.hasValidCredentials())
    }

    @Test
    public fun shouldNotHaveCredentialsWhenAccessTokenWillExpireAndNoRefreshTokenIsAvailable() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Assert.assertFalse(manager.hasValidCredentials(ONE_HOUR_SECONDS))
    }

    @Test
    public fun shouldHaveCredentialsWhenTokenHasExpiredButRefreshTokenIsAvailable() {
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn(null)
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    @Test
    public fun shouldNotHaveCredentialsWhenAccessTokenAndIdTokenAreMissing() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn(null)
        Assert.assertFalse(manager.hasValidCredentials())
    }

    @Test
    public fun shouldRecreateTheCredentials() {
        val credentialsManager = CredentialsManager(client, storage)
        val now = Date()
        val credentials = credentialsManager.recreateCredentials(
            "idTOKEN",
            "accessTOKEN",
            "tokenTYPE",
            "refreshTOKEN",
            now,
            "openid profile"
        )
        MatcherAssert.assertThat(credentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.idToken, Is.`is`("idTOKEN"))
        MatcherAssert.assertThat(credentials.accessToken, Is.`is`("accessTOKEN"))
        MatcherAssert.assertThat(credentials.type, Is.`is`("tokenTYPE"))
        MatcherAssert.assertThat(credentials.refreshToken, Is.`is`("refreshTOKEN"))
        MatcherAssert.assertThat(credentials.expiresAt, Is.`is`(now))
        MatcherAssert.assertThat(credentials.scope, Is.`is`("openid profile"))
    }

    @Test
    public fun shouldUseCustomClock() {
        val manager = CredentialsManager(client, storage)
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(false))

        //now, update the clock and retry
        manager.setClock(object : Clock {
            override fun getCurrentTimeMillis(): Long {
                return CredentialsMock.CURRENT_TIME_MS - 1000
            }
        })
        MatcherAssert.assertThat(manager.hasValidCredentials(), Is.`is`(true))
    }

    private fun prepareJwtDecoderMock(expiresAt: Date?) {
        val jwtMock = mock<JWT>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(expiresAt)
        Mockito.`when`(jwtDecoder.decode("idToken")).thenReturn(jwtMock)
    }

    private companion object {
        private const val ONE_HOUR_SECONDS = (60 * 60).toLong()
    }
}