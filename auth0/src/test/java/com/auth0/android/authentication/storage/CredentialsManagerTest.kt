package com.auth0.android.authentication.storage

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
import com.nhaarman.mockitokotlin2.verifyZeroInteractions
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.Assert
import org.junit.Assert.assertThrows
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
import java.util.Date
import java.util.concurrent.Executor

@RunWith(RobolectricTestRunner::class)
public class CredentialsManagerTest {
    @Mock
    private lateinit var client: AuthenticationAPIClient

    @Mock
    private lateinit var storage: Storage

    @Mock
    private lateinit var callback: Callback<Credentials, CredentialsManagerException>

    @Mock
    private lateinit var request: Request<Credentials, AuthenticationException>

    @Mock
    private lateinit var SSOCredentialsRequest: Request<SSOCredentials, AuthenticationException>

    @Mock
    private lateinit var ssoCallback: Callback<SSOCredentials, CredentialsManagerException>

    @Mock
    private lateinit var apiCredentialsCallback: Callback<APICredentials, CredentialsManagerException>

    @Mock
    private lateinit var jwtDecoder: JWTDecoder

    private val serialExecutor = Executor { runnable -> runnable.run() }

    private val credentialsCaptor: KArgumentCaptor<Credentials> = argumentCaptor()

    private val exceptionCaptor: KArgumentCaptor<CredentialsManagerException> = argumentCaptor()

    private val SSOCredentialsCaptor: KArgumentCaptor<SSOCredentials> = argumentCaptor()

    private val apiCredentialsCaptor: KArgumentCaptor<APICredentials> = argumentCaptor()

    @get:Rule
    public var exception: ExpectedException = ExpectedException.none()
    private lateinit var manager: CredentialsManager
    private lateinit var gson: Gson

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        val credentialsManager = CredentialsManager(client, storage, jwtDecoder, serialExecutor)
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
            CredentialsMock.create(idToken, accessToken, type, refreshToken, expiresAt, scope)
        }.`when`(manager).recreateCredentials(
            ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString(),
            ArgumentMatchers.anyString(),
            any(),
            ArgumentMatchers.anyString()
        )
        gson = GsonProvider.gson
    }

    @Test
    public fun shouldSaveRefreshableCredentialsInStorage() {
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
        val credentials: Credentials = CredentialsMock.create(
            "",
            "accessToken",
            "type",
            "refreshToken",
            Date(accessTokenExpirationTime),
            "scope"
        )
        prepareJwtDecoderMock(Date(accessTokenExpirationTime))
        manager.saveCredentials(credentials)
        verify(storage).store("com.auth0.id_token", "")
        verify(storage).store("com.auth0.access_token", "accessToken")
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", "type")
        verify(storage).store("com.auth0.expires_at", accessTokenExpirationTime)
        verify(storage).store("com.auth0.scope", "scope")
        verify(storage).store("com.auth0.cache_expires_at", accessTokenExpirationTime)
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldSaveRefreshableCredentialsIgnoringIdTokenExpForCacheExpirationInStorage() {
        val accessTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 5000 * 1000
        val idTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 2000 * 1000
        val credentials: Credentials = CredentialsMock.create(
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
        verify(storage).store("com.auth0.cache_expires_at", accessTokenExpirationTime)
        verifyNoMoreInteractions(storage)
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
    public fun shouldSaveApiCredentialsInStorage() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data"
        )
        val captor: KArgumentCaptor<String> = argumentCaptor()
        manager.saveApiCredentials(apiCredentials, "audience")
        verify(storage).store(captor.capture(), eq(gson.toJson(apiCredentials)))
        Assert.assertEquals("audience", captor.firstValue)
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldThrowOnSetIfCredentialsDoesNotHaveIdTokenOrAccessToken() {
        exception.expect(CredentialsManagerException::class.java)
        exception.expectMessage("Credentials must have a valid access_token or id_token value.")
        val credentials: Credentials =
            CredentialsMock.create("", "", "type", "refreshToken", Date(), null)
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSetIfCredentialsHasAccessTokenAndExpiresAt() {
        val credentials: Credentials =
            CredentialsMock.create("", "accessToken", "type", "refreshToken", Date(), null)
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotThrowOnSetIfCredentialsHasIdTokenAndExpiresAt() {
        verifyNoMoreInteractions(storage)
        val credentials: Credentials =
            CredentialsMock.create("idToken", "", "type", "refreshToken", Date(), null)
        prepareJwtDecoderMock(Date())
        manager.saveCredentials(credentials)
    }

    @Test
    public fun shouldNotSaveIfTheSSOCredentialsHasNoRefreshToken() {
        verifyZeroInteractions(storage)
        val ssoCredentials = SSOCredentialsMock.create(
            "accessToken", "identityToken",
            "issuedTokenType", "tokenType", null, 60
        )
        manager.saveSsoCredentials(ssoCredentials)
    }

    @Test
    public fun shouldNotSaveIfTheNewSSOCredentialRefreshTokenIsSameAsTheExistingOne() {
        verifyNoMoreInteractions(storage)
        val ssoCredentials = SSOCredentialsMock.create(
            "accessToken", "identityToken",
            "issuedTokenType", "tokenType", "refresh_token", 60
        )
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refresh_token")
        manager.saveSsoCredentials(ssoCredentials)
        verify(storage, times(0)).store("com.auth0.refresh_token", "refresh_token")
    }

    @Test
    public fun shouldSaveTheRefreshTokenIfTheNewSSOCredentialsRefreshTokenIsNotSameAsTheOldOne() {
        verifyNoMoreInteractions(storage)
        val ssoCredentials = SSOCredentialsMock.create(
            "accessToken", "identityToken",
            "issuedTokenType", "tokenType", "refresh_token", 60
        )
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refresh-token")
        manager.saveSsoCredentials(ssoCredentials)
        verify(storage).store("com.auth0.refresh_token", "refresh_token")
    }

    @Test
    public fun shouldThrowExceptionIfNoExistingRefreshTokenExistWhenGettingSSOCredentials() {
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn(null)
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
    public fun shouldSaveTheNewRefreshTokenWhenGettingTheSSOCredentials() {
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refresh_token_old")
        Mockito.`when`(client.ssoExchange("refresh_token_old"))
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
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onSuccess(
            SSOCredentialsCaptor.capture()
        )
        val credentials = SSOCredentialsCaptor.firstValue
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`("web-sso-token"))
        MatcherAssert.assertThat(credentials.tokenType, Is.`is`("token-type"))
        MatcherAssert.assertThat(credentials.issuedTokenType, Is.`is`("issued-token-type"))
        MatcherAssert.assertThat(credentials.refreshToken, Is.`is`("refresh-token"))
        MatcherAssert.assertThat(credentials.expiresIn, Is.`is`(60))
        verify(storage).store("com.auth0.refresh_token", credentials.refreshToken)
    }

    @Test
    public fun shouldFailOnGetNewSSOCredentialsWhenRefreshTokenExpired() {
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(
            client.ssoExchange("refreshToken")
        ).thenReturn(SSOCredentialsRequest)
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
    public fun shouldFailOnGetNewSSOCredentialsWhenUnexpectedErrorOccurs() {
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(
            client.ssoExchange("refreshToken")
        ).thenReturn(SSOCredentialsRequest)
        //Trigger failure
        val runtimeException = RuntimeException(
            "unexpected_error"
        )
        Mockito.`when`(SSOCredentialsRequest.execute()).thenThrow(runtimeException)
        manager.getSsoCredentials(ssoCallback)
        verify(ssoCallback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception, Is.`is`(CredentialsManagerException.UNKNOWN_ERROR))
        MatcherAssert.assertThat(exception.cause, Is.`is`(runtimeException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An unknown error has occurred while fetching the token. Please check the error cause for more details.")
        )
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldFailOnAwaitSSOCredentialsWhenNoRefreshTokenWasSaved(): Unit = runTest {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
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
    public fun shouldSaveNewRefreshingTokenOnAwaitSSOCredentials(): Unit = runTest {
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refresh_token_old")
        Mockito.`when`(client.ssoExchange("refresh_token_old"))
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
        val credentials = manager.awaitSsoCredentials()
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(credentials.sessionTransferToken, Is.`is`("web-sso-token"))
        MatcherAssert.assertThat(credentials.tokenType, Is.`is`("token-type"))
        MatcherAssert.assertThat(credentials.issuedTokenType, Is.`is`("issued-token-type"))
        MatcherAssert.assertThat(credentials.refreshToken, Is.`is`("refresh-token"))
        MatcherAssert.assertThat(credentials.expiresIn, Is.`is`(60))
        verify(storage).store("com.auth0.refresh_token", credentials.refreshToken)
    }


    @Test
    public fun shouldGetExistingAPICredentialsIfAlreadyPresentAndNotExpired() {
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            "token", "type",
            Date(accessTokenExpiry), "scope"
        )
        Mockito.`when`(storage.retrieveString("audience::scope")).thenReturn(gson.toJson(apiCredentials))
        manager.getApiCredentials("audience", "scope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(apiCredentialsCaptor.capture())
        val retrievedCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        Assert.assertEquals(retrievedCredentials.accessToken, apiCredentials.accessToken)
    }

    @Test
    public fun shouldThrowExceptionIfThereISNoRefreshTokenToGetNewApiToken() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
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
        Mockito.`when`(storage.retrieveString("audience::newScope")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
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
        manager.getApiCredentials("audience", "newScope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        // RefreshToken should not be replaced
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("audience::newScope", gson.toJson(renewedCredentials.toAPICredentials()))
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
        val accessTokenExpiry = CredentialsMock.CURRENT_TIME_MS - 3000
        val apiCredentials = ApiCredentialsMock.create(
            "token", "type",
            Date(accessTokenExpiry), "scope"
        )
        Mockito.`when`(storage.retrieveString("audience::scope")).thenReturn(gson.toJson(apiCredentials))
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
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
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "scope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getApiCredentials("audience", "scope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        // RefreshToken should not be replaced
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("audience::scope", gson.toJson(renewedCredentials.toAPICredentials()))
        // Verify the returned credentials are the latest
        val newAPiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldRenewApiCredentialsIfCurrentTokenWillExpireWithInMinTtl() {
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.CURRENT_TIME_MS - 10000
        val apiCredentials = ApiCredentialsMock.create(
            "token", "type",
            Date(accessTokenExpiry), "scope"
        )
        Mockito.`when`(storage.retrieveString("audience::scope")).thenReturn(gson.toJson(apiCredentials))
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
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
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "scope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getApiCredentials("audience", "scope", minTtl = 10, callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        // RefreshToken should not be replaced
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("audience::scope", gson.toJson(renewedCredentials.toAPICredentials()))
        // Verify the returned credentials are the latest
        val newAPiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldReplaceTheExistingRefreshTokenIfaNewOneIsObtainedInApiCredentials() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("audience")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience","newScope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "newRefreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getApiCredentials("audience", "newScope", callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onSuccess(
            apiCredentialsCaptor.capture()
        )

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        // RefreshToken should be replaced
        verify(storage).store("com.auth0.refresh_token", "newRefreshToken")
        verify(storage).store("audience::newScope", gson.toJson(renewedCredentials.toAPICredentials()))
        // Verify the returned credentials are the latest
        val newAPiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newAPiCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(newAPiCredentials.accessToken, Is.`is`("newAccess"))
        MatcherAssert.assertThat(newAPiCredentials.type, Is.`is`("newType"))
        MatcherAssert.assertThat(newAPiCredentials.expiresAt, Is.`is`(newDate))
        MatcherAssert.assertThat(newAPiCredentials.scope, Is.`is`("newScope"))
    }

    @Test
    public fun shouldThrowExceptionIfTheNewAPiCredentialTokenHasLowerLifetimeThanMinTTLRequested() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("audience")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(
            client.renewAuth("refreshToken", "audience", "newScope")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.CURRENT_TIME_MS + 1 * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getApiCredentials("audience", "newScope", minTtl = 1, callback = apiCredentialsCallback)
        verify(apiCredentialsCallback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        Assert.assertEquals(
            "The lifetime of the renewed Access Token (0) is less than the minTTL requested (1). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.",
            exception.message
        )
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitNonExpiredApiCredentialsFromStorage(): Unit = runTest {
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            "token", "type",
            Date(accessTokenExpiry), "scope"
        )
        Mockito.`when`(storage.retrieveString("audience::scope")).thenReturn(gson.toJson(apiCredentials))
        val retrievedCredentials = manager.awaitApiCredentials("audience", "scope")
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        Assert.assertEquals(retrievedCredentials.accessToken, apiCredentials.accessToken)
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitNewApiCredentialsIfOneIsNotStored(): Unit = runTest {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("audience")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refresh_token")

        Mockito.`when`(
            client.renewAuth("refresh_token", "audience")
        ).thenReturn(request)
        val newDate = Date(CredentialsMock.CURRENT_TIME_MS + 1 * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType",null, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        val retrievedCredentials = manager.awaitApiCredentials("audience")
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        Assert.assertEquals(retrievedCredentials.accessToken, renewedCredentials.accessToken)
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
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitNonExpiredCredentialsFromStorage(): Unit = runTest {
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
        val retrievedCredentials = manager.awaitCredentials()
        MatcherAssert.assertThat(retrievedCredentials, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("accessToken"))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldFailOnAwaitCredentialsWhenExpiredAndNoRefreshTokenWasSaved(): Unit = runTest {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.CURRENT_TIME_MS //Same as current time --> expired
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
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
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`(""))
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`("idToken"))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expirationTime))
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
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`(""))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    @Test
    public fun shouldRenewCredentialsIfSavedScopeIsNullAndRequiredScopeIsNotNull() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS // non expired credentials
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn(null)
        Mockito.`when`(
            client.renewAuth("refreshToken")
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
        manager.getCredentials("some scope", 0, callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(request)
            .addParameter(eq("scope"), eq("some scope"))

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh)
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt.time
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
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "some scope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getCredentials("some scope", 0, callback)
        verify(request)
            .addParameter(eq("scope"), eq("some scope"))
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
            "com.auth0.expires_at", renewedCredentials.expiresAt.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt.time
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
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getCredentials("some scope", 0, callback)
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(request)
            .addParameter(eq("scope"), eq("some scope"))
        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh)
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt.time
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
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())

        // Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getCredentials(null, 60, callback) // 60 seconds of minTTL
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
            "com.auth0.expires_at", renewedCredentials.expiresAt.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt.time
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
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        //Trigger success
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getCredentials(null, 60, callback) // 60 seconds of minTTL
        verify(callback).onSuccess(
            credentialsCaptor.capture()
        )
        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.idToken)
        verify(storage).store("com.auth0.access_token", renewedCredentials.accessToken)
        //RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh)
        verify(storage).store("com.auth0.refresh_token", "refreshToken")
        verify(storage).store("com.auth0.token_type", renewedCredentials.type)
        verify(storage).store(
            "com.auth0.expires_at", renewedCredentials.expiresAt.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt.time
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
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())

        // Trigger failure
        val newRefresh: String? = null
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getCredentials(null, 60, callback) // 60 seconds of minTTL
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
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        verify(request, never())
            .addParameter(eq("scope"), ArgumentMatchers.anyString())

        //Trigger success
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getCredentials(callback)
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
            "com.auth0.expires_at", renewedCredentials.expiresAt.time
        )
        verify(storage).store("com.auth0.scope", renewedCredentials.scope)
        verify(storage).store(
            "com.auth0.cache_expires_at", renewedCredentials.expiresAt.time
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
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenRefreshTokenExpired() {
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
        //Trigger failure
        val authenticationException = AuthenticationException(
            "invalid_grant",
            "Unknown or invalid refresh token."
        )
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
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
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenUserIsDeleted() {
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
        //Trigger failure
        val authenticationException = AuthenticationException(
            mapOf(
                "error" to "invalid_grant",
                "error_description" to "The refresh_token was generated for a user who doesn't exist anymore."
            ), 403
        )
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
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
    public fun shouldGetAndFailToRenewExpiredCredentialsWhenNetworkIsNotAvailable() {
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
        //Trigger failure
        val authenticationException = AuthenticationException(
            "Failed to execute the network request", NetworkErrorException(mock())
        )
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
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
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
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
        //Trigger failure
        val authenticationException =
            AuthenticationException("Something went wrong", mock<Exception>())
        Mockito.`when`(request.execute()).thenThrow(authenticationException)
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
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
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
        //Trigger failure
        val runtimeException = NullPointerException("Something went wrong")
        Mockito.`when`(request.execute()).thenThrow(runtimeException)
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
        verify(callback).onFailure(
            exceptionCaptor.capture()
        )
        val exception = exceptionCaptor.firstValue
        MatcherAssert.assertThat(exception, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(exception, Is.`is`(CredentialsManagerException.UNKNOWN_ERROR))
        MatcherAssert.assertThat(exception.cause, Is.`is`(runtimeException))
        MatcherAssert.assertThat(
            exception.message,
            Is.`is`("An unknown error has occurred while fetching the token. Please check the error cause for more details.")
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
    public fun shouldClearApiCredentials() {
        val captor = argumentCaptor<String>()
        manager.clearApiCredentials("audience")
        verify(storage).remove(captor.capture())
        Assert.assertEquals("audience", captor.firstValue)
        verifyNoMoreInteractions(storage)
    }

    @Test
    public fun shouldSaveApiCredentialsWithScopeAsKey() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data write:data"
        )

        manager.saveApiCredentials(apiCredentials, "audience", "read:data write:data")

        verify(storage).store(
            eq("audience::read:data::write:data"),
            eq(gson.toJson(apiCredentials))
        )
    }

    @Test
    public fun shouldSaveApiCredentialsWithoutScopeUsingOnlyAudience() {
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = APICredentials(
            accessToken = "apiAccessToken",
            type = "type",
            expiresAt = Date(expirationTime),
            scope = "read:data"
        )

        manager.saveApiCredentials(apiCredentials, "audience", null)

        verify(storage).store(eq("audience"), eq(gson.toJson(apiCredentials)))
    }

    @Test
    public fun shouldSaveApiCredentialsWithDifferentScopesUnderDifferentKeys() {
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

        manager.saveApiCredentials(apiCredentials1, "audience", "read:data")
        manager.saveApiCredentials(apiCredentials2, "audience", "write:data")

        verify(storage).store(eq("audience::read:data"), eq(gson.toJson(apiCredentials1)))
        verify(storage).store(eq("audience::write:data"), eq(gson.toJson(apiCredentials2)))
    }

    @Test
    public fun shouldClearApiCredentialsWithScope() {
        manager.clearApiCredentials("audience", "read:data write:data")
        verify(storage).remove("audience::read:data::write:data")
    }

    @Test
    public fun shouldClearApiCredentialsWithoutScopeUsingAudienceOnly() {
        manager.clearApiCredentials("audience", null)
        verify(storage).remove("audience")
    }

    @Test
    public fun shouldClearApiCredentialsWithDefaultNullScope() {
        manager.clearApiCredentials("audience")
        verify(storage).remove("audience")
    }

    @Test
    public fun shouldGetApiCredentialsWithSpecificScope() {
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            accessToken = "apiToken",
            expiresAt = Date(accessTokenExpiry),
            scope = "read:data"
        )
        Mockito.`when`(storage.retrieveString("audience::read:data"))
            .thenReturn(gson.toJson(apiCredentials))

        manager.getApiCredentials("audience", "read:data", callback = apiCredentialsCallback)

        verify(apiCredentialsCallback).onSuccess(apiCredentialsCaptor.capture())
        val retrievedCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("apiToken"))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("read:data"))
    }

    @Test
    public fun shouldGetApiCredentialsWithoutScopeFromAudienceKey() {
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            accessToken = "apiToken",
            expiresAt = Date(accessTokenExpiry),
            scope = "openid"
        )
        Mockito.`when`(storage.retrieveString("audience"))
            .thenReturn(gson.toJson(apiCredentials))

        manager.getApiCredentials("audience", null, callback = apiCredentialsCallback)

        verify(apiCredentialsCallback).onSuccess(apiCredentialsCaptor.capture())
        val retrievedCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(retrievedCredentials.accessToken, Is.`is`("apiToken"))
    }

    @Test
    public fun shouldRenewApiCredentialsWhenRequestingScopeButStoredUnderDifferentScopeKey() {
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveString("audience::write:data"))
            .thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refreshToken")
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

        manager.getApiCredentials("audience", "write:data", callback = apiCredentialsCallback)

        verify(apiCredentialsCallback).onSuccess(apiCredentialsCaptor.capture())
        val newApiCredentials = apiCredentialsCaptor.firstValue
        MatcherAssert.assertThat(newApiCredentials.scope, Is.`is`("write:data"))
        MatcherAssert.assertThat(newApiCredentials.accessToken, Is.`is`("newAccess"))
        verify(storage).store(eq("audience::write:data"), any<String>())
    }

    @Test
    public fun shouldStoreApiCredentialsUnderCorrectKeyWhenRenewing() {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("audience::custom:scope"))
            .thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refreshToken")
        Mockito.`when`(client.renewAuth("refreshToken", "audience", "custom:scope"))
            .thenReturn(request)

        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)

        val renewedCredentials = Credentials(
            "newId", "newAccess", "newType", null, newDate, "custom:scope"
        )
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)

        manager.getApiCredentials("audience", "custom:scope", callback = apiCredentialsCallback)

        verify(storage).store(eq("audience::custom:scope"), any<String>())
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitApiCredentialsWithSpecificScope(): Unit = runTest {
        verifyNoMoreInteractions(client)
        val accessTokenExpiry = CredentialsMock.ONE_HOUR_AHEAD_MS
        val apiCredentials = ApiCredentialsMock.create(
            accessToken = "apiToken",
            expiresAt = Date(accessTokenExpiry),
            scope = "read:data"
        )
        Mockito.`when`(storage.retrieveString("audience::read:data"))
            .thenReturn(gson.toJson(apiCredentials))

        val result = manager.awaitApiCredentials("audience", "read:data")

        MatcherAssert.assertThat(result.accessToken, Is.`is`("apiToken"))
        MatcherAssert.assertThat(result.scope, Is.`is`("read:data"))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitAndRenewApiCredentialsWithScope(): Unit = runTest {
        verifyNoMoreInteractions(client)
        Mockito.`when`(storage.retrieveString("audience::write:data"))
            .thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token"))
            .thenReturn("refreshToken")
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

        val result = manager.awaitApiCredentials("audience", "write:data")

        MatcherAssert.assertThat(result.scope, Is.`is`("write:data"))
        MatcherAssert.assertThat(result.accessToken, Is.`is`("newAccess"))
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

    @Test(expected = IllegalArgumentException::class)
    public fun shouldUseCustomExecutorForGetCredentials() {
        val manager = CredentialsManager(client, storage, jwtDecoder) {
            throw IllegalArgumentException("Proper Executor Set")
        }
        manager.getCredentials(object : Callback<Credentials, CredentialsManagerException> {
            override fun onSuccess(result: Credentials) {}
            override fun onFailure(error: CredentialsManagerException) {}
        })
    }


    @Test
    public fun shouldAddParametersToRequest() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS // non expired credentials
        val parameters = mapOf(
            "client_id" to "new Client ID",
            "phone" to "+1 (777) 124-1588"
        )
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("oldscope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        val renewedCredentials =
            Credentials("newId", "newAccess", "newType", "newRefresh", newDate, "newScope")
        Mockito.`when`(request.execute()).thenReturn(renewedCredentials)
        manager.getCredentials(
            scope = "some changed scope to trigger refresh",
            minTtl = 0,
            parameters = parameters,
            callback = callback
        )
        verify(request).addParameters(parameters)
        verify(request).execute()
    }

    @Test
    public fun shouldReturnNewCredentialsIfForced() {
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken")
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS // non expired credentials
        val parameters = mapOf(
            "client_id" to "new Client ID",
            "phone" to "+1 (777) 124-1588"
        )
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("oldscope")
        Mockito.`when`(
            client.renewAuth("refreshToken")
        ).thenReturn(request)

        val newDate = Date(CredentialsMock.ONE_HOUR_AHEAD_MS)
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(newDate)
        Mockito.`when`(jwtDecoder.decode("newId")).thenReturn(jwtMock)
        val expectedCredentials =
            Credentials("newId", "newAccess", "newType", "newRefresh", newDate, "oldscope")
        Mockito.`when`(request.execute()).thenReturn(expectedCredentials)
        manager.getCredentials(
            scope = "oldscope",
            minTtl = 0,
            parameters = parameters,
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
        Mockito.`when`(storage.retrieveString("com.auth0.id_token")).thenReturn(null)
        Mockito.`when`(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken")
        Mockito.`when`(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken")
        Mockito.`when`(storage.retrieveString("com.auth0.token_type")).thenReturn("type")
        val expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS
        Mockito.`when`(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveLong("com.auth0.cache_expires_at"))
            .thenReturn(expirationTime)
        Mockito.`when`(storage.retrieveString("com.auth0.scope")).thenReturn("scope")
        manager.getCredentials(
            "scope",
            0,
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
        MatcherAssert.assertThat(retrievedCredentials.idToken, Is.`is`(""))
        MatcherAssert.assertThat(retrievedCredentials.refreshToken, Is.`is`("refreshToken"))
        MatcherAssert.assertThat(retrievedCredentials.type, Is.`is`("type"))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(retrievedCredentials.expiresAt.time, Is.`is`(expirationTime))
        MatcherAssert.assertThat(retrievedCredentials.scope, Is.`is`("scope"))
    }

    private fun prepareJwtDecoderMock(expiresAt: Date?) {
        val jwtMock = mock<Jwt>()
        Mockito.`when`(jwtMock.expiresAt).thenReturn(expiresAt)
        Mockito.`when`(jwtDecoder.decode("idToken")).thenReturn(jwtMock)
    }

    private companion object {
        private const val ONE_HOUR_SECONDS = (60 * 60).toLong()
    }
}