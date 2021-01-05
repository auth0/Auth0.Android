package com.auth0.android.authentication.storage

import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.BaseCallback
import com.auth0.android.jwt.JWT
import com.auth0.android.request.Request
import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.auth0.android.util.Clock
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
import org.mockito.*
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

    @Captor
    private lateinit var credentialsCaptor: ArgumentCaptor<Credentials>

    @Captor
    private lateinit var exceptionCaptor: ArgumentCaptor<CredentialsManagerException>

    @get:Rule
    public var exception: ExpectedException = ExpectedException.none()
    private lateinit var manager: CredentialsManager

    @Captor
    private lateinit var requestCallbackCaptor: ArgumentCaptor<BaseCallback<Credentials, AuthenticationException>>

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
            ArgumentMatchers.any(
                Date::class.java
            ),
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
        Mockito.verify(storage).store("com.auth0.id_token", "idToken")
        Mockito.verify(storage).store("com.auth0.access_token", "accessToken")
        Mockito.verify(storage).store("com.auth0.refresh_token", "refreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", "type")
        Mockito.verify(storage).store("com.auth0.expires_at", expirationTime)
        Mockito.verify(storage).store("com.auth0.scope", "scope")
        Mockito.verify(storage).store("com.auth0.cache_expires_at", expirationTime)
        Mockito.verifyNoMoreInteractions(storage)
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
        Mockito.verify(storage).store("com.auth0.id_token", null as String?)
        Mockito.verify(storage).store("com.auth0.access_token", "accessToken")
        Mockito.verify(storage).store("com.auth0.refresh_token", "refreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", "type")
        Mockito.verify(storage).store("com.auth0.expires_at", accessTokenExpirationTime)
        Mockito.verify(storage).store("com.auth0.scope", "scope")
        Mockito.verify(storage).store("com.auth0.cache_expires_at", accessTokenExpirationTime)
        Mockito.verifyNoMoreInteractions(storage)
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
        Mockito.verify(storage).store("com.auth0.id_token", "idToken")
        Mockito.verify(storage).store("com.auth0.access_token", "accessToken")
        Mockito.verify(storage).store("com.auth0.refresh_token", "refreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", "type")
        Mockito.verify(storage).store("com.auth0.expires_at", accessTokenExpirationTime)
        Mockito.verify(storage).store("com.auth0.scope", "scope")
        Mockito.verify(storage).store("com.auth0.cache_expires_at", idTokenExpirationTime)
        Mockito.verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldSaveNonRefreshableCredentialsInStorage() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val credentials: Credentials =
            CredentialsMock("idToken", "accessToken", "type", null, Date(expirationTime), "scope")
        prepareJwtDecoderMock(Date(expirationTime))
        manager.saveCredentials(credentials)
        Mockito.verify(storage).store("com.auth0.id_token", "idToken")
        Mockito.verify(storage).store("com.auth0.access_token", "accessToken")
        Mockito.verify(storage).store("com.auth0.refresh_token", null as String?)
        Mockito.verify(storage).store("com.auth0.token_type", "type")
        Mockito.verify(storage).store("com.auth0.expires_at", expirationTime)
        Mockito.verify(storage).store("com.auth0.scope", "scope")
        Mockito.verify(storage).store("com.auth0.cache_expires_at", expirationTime)
        Mockito.verifyNoMoreInteractions(storage)
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
        Mockito.verifyNoMoreInteractions(client)
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
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        manager.getCredentials(callback)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.value
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("Credentials need to be renewed but no Refresh Token is available to renew them.")
        )
    }

    @Test
    public fun shouldNotFailOnGetCredentialsWhenCacheExpiresAtNotSetButExpiresAtIsPresent() {
        Mockito.verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        manager.getCredentials(callback)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
    }

    @Test
    public fun shouldGetNonExpiredCredentialsFromStorage() {
        Mockito.verifyNoMoreInteractions(client)
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
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
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
        Mockito.verifyNoMoreInteractions(client)
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
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
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
        Mockito.verifyNoMoreInteractions(client)
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
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        val retrievedCredentials = credentialsCaptor.value
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
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials("some scope", 0, callback)
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )
        Mockito.verify(request)
            .addParameter(ArgumentMatchers.eq("scope"), ArgumentMatchers.eq("some scope"))

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "some scope")
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        Mockito.verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        Mockito.verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        Mockito.verify(storage, Mockito.never()).store("com.auth0.refresh_token", newRefresh)
        Mockito.verify(storage).store("com.auth0.refresh_token", "refreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        Mockito.verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        Mockito.verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage, Mockito.never()).remove(ArgumentMatchers.anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
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
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials("some scope", 0, callback)
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )
        Mockito.verify(request)
            .addParameter(ArgumentMatchers.eq("scope"), ArgumentMatchers.eq("some scope"))

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        Mockito.verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        Mockito.verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        Mockito.verify(storage, Mockito.never()).store("com.auth0.refresh_token", newRefresh)
        Mockito.verify(storage).store("com.auth0.refresh_token", "refreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        Mockito.verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        Mockito.verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage, Mockito.never()).remove(ArgumentMatchers.anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
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
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(null, 60, callback) // 60 seconds of minTTL
        Mockito.verify(request, Mockito.never())
            .addParameter(ArgumentMatchers.eq("scope"), ArgumentMatchers.anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        Mockito.verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        Mockito.verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        Mockito.verify(storage, Mockito.never()).store("com.auth0.refresh_token", newRefresh)
        Mockito.verify(storage).store("com.auth0.refresh_token", "refreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        Mockito.verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        Mockito.verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage, Mockito.never()).remove(ArgumentMatchers.anyString())

        // Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
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
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(callback)
        Mockito.verify(request, Mockito.never())
            .addParameter(ArgumentMatchers.eq("scope"), ArgumentMatchers.anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        //Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        Mockito.verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        Mockito.verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        //RefreshToken should not be replaced
        Mockito.verify(storage, Mockito.never()).store("com.auth0.refresh_token", newRefresh)
        Mockito.verify(storage).store("com.auth0.refresh_token", "refreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        Mockito.verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        Mockito.verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage, Mockito.never()).remove(ArgumentMatchers.anyString())

        //// Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
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
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(null, 60, callback) // 60 seconds of minTTL
        Mockito.verify(request, Mockito.never())
            .addParameter(ArgumentMatchers.eq("scope"), ArgumentMatchers.anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        // Trigger failure
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onFailure(
            exceptionCaptor.capture()
        )

        // Verify the credentials are never stored
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt())
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong())
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyBoolean())
        Mockito.verify(storage, Mockito.never()).remove(ArgumentMatchers.anyString())
        val exception = exceptionCaptor.value
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
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        manager.getCredentials(callback)
        Mockito.verify(request, Mockito.never())
            .addParameter(ArgumentMatchers.eq("scope"), ArgumentMatchers.anyString())
        Mockito.verify(request).start(
            requestCallbackCaptor.capture()
        )

        //Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope")
        requestCallbackCaptor.value.onSuccess(renewedCredentials)
        Mockito.verify(callback).onSuccess(
            credentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        Mockito.verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        Mockito.verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        //RefreshToken should be replaced
        Mockito.verify(storage).store("com.auth0.refresh_token", "rotatedRefreshToken")
        Mockito.verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        Mockito.verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        Mockito.verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt!!.time
        )
        Mockito.verify(storage, Mockito.never()).remove(ArgumentMatchers.anyString())

        //// Verify the returned credentials are the latest
        val retrievedCredentials = credentialsCaptor.value
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
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt())
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong())
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyString())
        Mockito.verify(storage, Mockito.never())
            .store(ArgumentMatchers.anyString(), ArgumentMatchers.anyBoolean())
        Mockito.verify(storage, Mockito.never()).remove(ArgumentMatchers.anyString())
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
        val exception = exceptionCaptor.value
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
        Mockito.verify(storage).remove("com.auth0.id_token")
        Mockito.verify(storage).remove("com.auth0.access_token")
        Mockito.verify(storage).remove("com.auth0.refresh_token")
        Mockito.verify(storage).remove("com.auth0.token_type")
        Mockito.verify(storage).remove("com.auth0.expires_at")
        Mockito.verify(storage).remove("com.auth0.scope")
        Mockito.verify(storage).remove("com.auth0.cache_expires_at")
        Mockito.verifyNoMoreInteractions(storage)
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
        val jwtMock = Mockito.mock(JWT::class.java)
        Mockito.`when`(jwtMock.expiresAt).thenReturn(expiresAt)
        Mockito.`when`(jwtDecoder.decode("idToken")).thenReturn(jwtMock)
    }

    private companion object {
        private const val ONE_HOUR_SECONDS = (60 * 60).toLong()
    }
}