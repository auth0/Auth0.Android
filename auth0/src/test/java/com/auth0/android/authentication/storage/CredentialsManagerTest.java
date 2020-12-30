package com.auth0.android.authentication.storage;

import androidx.annotation.Nullable;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.JWT;
import com.auth0.android.request.Request;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.auth0.android.util.Clock;

import org.hamcrest.CoreMatchers;
import org.hamcrest.core.Is;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class CredentialsManagerTest {

    private static final long ONE_HOUR_SECONDS = 60 * 60;

    @Mock
    private AuthenticationAPIClient client;
    @Mock
    private Storage storage;
    @Mock
    private BaseCallback<Credentials, CredentialsManagerException> callback;
    @Mock
    private Request<Credentials, AuthenticationException> request;
    @Mock
    private JWTDecoder jwtDecoder;
    @Captor
    private ArgumentCaptor<Credentials> credentialsCaptor;
    @Captor
    private ArgumentCaptor<CredentialsManagerException> exceptionCaptor;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private CredentialsManager manager;
    @Captor
    private ArgumentCaptor<BaseCallback<Credentials, AuthenticationException>> requestCallbackCaptor;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        CredentialsManager credentialsManager = new CredentialsManager(client, storage, jwtDecoder);
        manager = spy(credentialsManager);
        //Needed to test expiration verification
        doReturn(CredentialsMock.CURRENT_TIME_MS).when(manager).getCurrentTimeInMillis();
        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                String idToken = invocation.getArgument(0, String.class);
                String accessToken = invocation.getArgument(1, String.class);
                String type = invocation.getArgument(2, String.class);
                String refreshToken = invocation.getArgument(3, String.class);
                Date expiresAt = invocation.getArgument(4, Date.class);
                String scope = invocation.getArgument(5, String.class);
                return new CredentialsMock(idToken, accessToken, type, refreshToken, expiresAt, scope);
            }
        }).when(manager).recreateCredentials(anyString(), anyString(), anyString(), anyString(), any(Date.class), anyString());
    }

    @Test
    public void shouldSaveRefreshableCredentialsInStorage() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(expirationTime), "scope");
        prepareJwtDecoderMock(new Date(expirationTime));
        manager.saveCredentials(credentials);

        verify(storage).store("com.auth0.id_token", "idToken");
        verify(storage).store("com.auth0.access_token", "accessToken");
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", "type");
        verify(storage).store("com.auth0.expires_at", expirationTime);
        verify(storage).store("com.auth0.scope", "scope");
        verify(storage).store("com.auth0.cache_expires_at", expirationTime);
        verifyNoMoreInteractions(storage);
    }

    @Test
    public void shouldSaveRefreshableCredentialsUsingAccessTokenExpForCacheExpirationInStorage() {
        long accessTokenExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock(null, "accessToken", "type", "refreshToken", new Date(accessTokenExpirationTime), "scope");
        prepareJwtDecoderMock(new Date(accessTokenExpirationTime));
        manager.saveCredentials(credentials);

        verify(storage).store("com.auth0.id_token", (String) null);
        verify(storage).store("com.auth0.access_token", "accessToken");
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", "type");
        verify(storage).store("com.auth0.expires_at", accessTokenExpirationTime);
        verify(storage).store("com.auth0.scope", "scope");
        verify(storage).store("com.auth0.cache_expires_at", accessTokenExpirationTime);
        verifyNoMoreInteractions(storage);
    }

    @Test
    public void shouldSaveRefreshableCredentialsUsingIdTokenExpForCacheExpirationInStorage() {
        long accessTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 5000 * 1000;
        long idTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 2000 * 1000;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(accessTokenExpirationTime), "scope");
        prepareJwtDecoderMock(new Date(idTokenExpirationTime));
        manager.saveCredentials(credentials);

        verify(storage).store("com.auth0.id_token", "idToken");
        verify(storage).store("com.auth0.access_token", "accessToken");
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", "type");
        verify(storage).store("com.auth0.expires_at", accessTokenExpirationTime);
        verify(storage).store("com.auth0.scope", "scope");
        verify(storage).store("com.auth0.cache_expires_at", idTokenExpirationTime);
        verifyNoMoreInteractions(storage);
    }

    @Test
    public void shouldSaveNonRefreshableCredentialsInStorage() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", null, new Date(expirationTime), "scope");
        prepareJwtDecoderMock(new Date(expirationTime));
        manager.saveCredentials(credentials);

        verify(storage).store("com.auth0.id_token", "idToken");
        verify(storage).store("com.auth0.access_token", "accessToken");
        verify(storage).store("com.auth0.refresh_token", (String) null);
        verify(storage).store("com.auth0.token_type", "type");
        verify(storage).store("com.auth0.expires_at", expirationTime);
        verify(storage).store("com.auth0.scope", "scope");
        verify(storage).store("com.auth0.cache_expires_at", expirationTime);
        verifyNoMoreInteractions(storage);
    }

    @Test
    public void shouldThrowOnSetIfCredentialsDoesNotHaveIdTokenOrAccessToken() {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.");

        Credentials credentials = new CredentialsMock(null, null, "type", "refreshToken", 123456L);
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldThrowOnSetIfCredentialsDoesNotHaveExpiresAt() {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.");

        Date date = null;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope");
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSetIfCredentialsHaveAccessTokenAndExpiresIn() {
        Credentials credentials = new CredentialsMock(null, "accessToken", "type", "refreshToken", 123456L);
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSetIfCredentialsHaveIdTokenAndExpiresIn() {
        Credentials credentials = new CredentialsMock("idToken", null, "type", "refreshToken", 123456L);
        prepareJwtDecoderMock(new Date());
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldFailOnGetCredentialsWhenNoAccessTokenOrIdTokenWasSaved() {
        verifyNoMoreInteractions(client);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.access_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldFailOnGetCredentialsWhenExpiredAndNoRefreshTokenWasSaved() {
        verifyNoMoreInteractions(client);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("Credentials need to be renewed but no Refresh Token is available to renew them."));
    }

    @Test
    public void shouldNotFailOnGetCredentialsWhenCacheExpiresAtNotSetButExpiresAtIsPresent() {
        verifyNoMoreInteractions(client);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(null);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");

        manager.getCredentials(callback);

        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorage() {
        verifyNoMoreInteractions(client);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is("accessToken"));
        assertThat(retrievedCredentials.getIdToken(), is("idToken"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresIn(), is(notNullValue()));
        // TODO [SDK-2184]: fix clock mocking to avoid CredentialsManager expiresIn calculation
        assertThat(retrievedCredentials.getExpiresIn().doubleValue(), CoreMatchers.is(closeTo(ONE_HOUR_SECONDS, 50)));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expirationTime));
        assertThat(retrievedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() {
        verifyNoMoreInteractions(client);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is(nullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("idToken"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresIn(), is(notNullValue()));
        // TODO [SDK-2184]: fix clock mocking to avoid CredentialsManager expiresIn calculation
        assertThat(retrievedCredentials.getExpiresIn().doubleValue(), CoreMatchers.is(closeTo(ONE_HOUR_SECONDS, 50)));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expirationTime));
        assertThat(retrievedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyAccessTokenIsAvailable() {
        verifyNoMoreInteractions(client);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        Long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is("accessToken"));
        assertThat(retrievedCredentials.getIdToken(), is(nullValue()));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresIn(), is(notNullValue()));
        // TODO [SDK-2184]: fix clock mocking to avoid CredentialsManager expiresIn calculation
        assertThat(retrievedCredentials.getExpiresIn().doubleValue(), CoreMatchers.is(closeTo(ONE_HOUR_SECONDS, 50)));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expirationTime));
        assertThat(retrievedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldRenewExpiredCredentialsWhenScopeHasChanged() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; // expired credentials
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");
        when(client.renewAuth("refreshToken")).thenReturn(request);

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);

        manager.getCredentials("some scope", 0, callback);
        verify(request).start(requestCallbackCaptor.capture());
        verify(request).addParameter(eq("scope"), eq("some scope"));

        // Trigger success
        String newRefresh = null;
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", newRefresh, newDate, "some scope");
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.getIdToken());
        verify(storage).store("com.auth0.access_token", renewedCredentials.getAccessToken());
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh);
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", renewedCredentials.getType());
        verify(storage).store("com.auth0.expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage).store("com.auth0.scope", renewedCredentials.getScope());
        verify(storage).store("com.auth0.cache_expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage, never()).remove(anyString());

        // Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("some scope"));
    }

    @Test
    public void shouldRenewCredentialsWhenScopeHasChanged() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS; // non expired credentials
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("some new scope");
        when(client.renewAuth("refreshToken")).thenReturn(request);

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);

        manager.getCredentials("some scope", 0, callback);
        verify(request).start(requestCallbackCaptor.capture());
        verify(request).addParameter(eq("scope"), eq("some scope"));

        // Trigger success
        String newRefresh = null;
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope");
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.getIdToken());
        verify(storage).store("com.auth0.access_token", renewedCredentials.getAccessToken());
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh);
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", renewedCredentials.getType());
        verify(storage).store("com.auth0.expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage).store("com.auth0.scope", renewedCredentials.getScope());
        verify(storage).store("com.auth0.cache_expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage, never()).remove(anyString());

        // Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("newScope"));
    }

    @Test
    public void shouldRenewCredentialsWithMinTtl() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; // Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");
        when(client.renewAuth("refreshToken")).thenReturn(request);

        Date newDate = new Date(CredentialsMock.CURRENT_TIME_MS + 61 * 1000); // New token expires in minTTL + 1 second
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);

        manager.getCredentials(null, 60, callback); // 60 seconds of minTTL
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        // Trigger success
        String newRefresh = null;
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope");
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.getIdToken());
        verify(storage).store("com.auth0.access_token", renewedCredentials.getAccessToken());
        // RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh);
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", renewedCredentials.getType());
        verify(storage).store("com.auth0.expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage).store("com.auth0.scope", renewedCredentials.getScope());
        verify(storage).store("com.auth0.cache_expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage, never()).remove(anyString());

        // Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("newScope"));
    }

    @Test
    public void shouldGetAndSuccessfullyRenewExpiredCredentials() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");
        when(client.renewAuth("refreshToken")).thenReturn(request);

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);

        manager.getCredentials(callback);
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        //Trigger success
        String newRefresh = null;
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope");
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.getIdToken());
        verify(storage).store("com.auth0.access_token", renewedCredentials.getAccessToken());
        //RefreshToken should not be replaced
        verify(storage, never()).store("com.auth0.refresh_token", newRefresh);
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", renewedCredentials.getType());
        verify(storage).store("com.auth0.expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage).store("com.auth0.scope", renewedCredentials.getScope());
        verify(storage).store("com.auth0.cache_expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage, never()).remove(anyString());

        //// Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("newScope"));
    }

    @Test
    public void shouldGetAndFailToRenewExpiredCredentialsWhenReceivedTokenHasLowerTtl() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; // Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");
        when(client.renewAuth("refreshToken")).thenReturn(request);

        Date newDate = new Date(CredentialsMock.CURRENT_TIME_MS + 59 * 1000); // New token expires in minTTL - 1 second
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);

        manager.getCredentials(null, 60, callback); // 60 seconds of minTTL
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        // Trigger failure
        String newRefresh = null;
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", newRefresh, newDate, "newScope");
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onFailure(exceptionCaptor.capture());

        // Verify the credentials are never stored
        verify(storage, never()).store(anyString(), anyInt());
        verify(storage, never()).store(anyString(), anyLong());
        verify(storage, never()).store(anyString(), anyString());
        verify(storage, never()).store(anyString(), anyBoolean());
        verify(storage, never()).remove(anyString());

        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCause(), is(nullValue()));
        assertThat(exception.getMessage(), is("The lifetime of the renewed Access Token (1) is less than the minTTL requested (60). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL."));
    }

    @Test
    public void shouldGetAndSuccessfullyRenewExpiredCredentialsWithRefreshTokenRotation() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");
        when(client.renewAuth("refreshToken")).thenReturn(request);

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);

        manager.getCredentials(callback);
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        //Trigger success
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope");
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());

        // Verify the credentials are property stored
        verify(storage).store("com.auth0.id_token", renewedCredentials.getIdToken());
        verify(storage).store("com.auth0.access_token", renewedCredentials.getAccessToken());
        //RefreshToken should be replaced
        verify(storage).store("com.auth0.refresh_token", "rotatedRefreshToken");
        verify(storage).store("com.auth0.token_type", renewedCredentials.getType());
        verify(storage).store("com.auth0.expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage).store("com.auth0.scope", renewedCredentials.getScope());
        verify(storage).store("com.auth0.cache_expires_at", renewedCredentials.getExpiresAt().getTime());
        verify(storage, never()).remove(anyString());

        //// Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("rotatedRefreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("newScope"));
    }

    @Test
    public void shouldGetAndFailToRenewExpiredCredentials() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieveString("com.auth0.token_type")).thenReturn("type");
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.scope")).thenReturn("scope");
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(callback);
        verify(storage, never()).store(anyString(), anyInt());
        verify(storage, never()).store(anyString(), anyLong());
        verify(storage, never()).store(anyString(), anyString());
        verify(storage, never()).store(anyString(), anyBoolean());
        verify(storage, never()).remove(anyString());
        verify(request).start(requestCallbackCaptor.capture());

        //Trigger failure
        AuthenticationException authenticationException = mock(AuthenticationException.class);
        requestCallbackCaptor.getValue().onFailure(authenticationException);
        verify(callback).onFailure(exceptionCaptor.capture());

        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCause(), Is.<Throwable>is(authenticationException));
        assertThat(exception.getMessage(), is("An error occurred while trying to use the Refresh Token to renew the Credentials."));
    }

    @Test
    public void shouldClearCredentials() {
        manager.clearCredentials();

        verify(storage).remove("com.auth0.id_token");
        verify(storage).remove("com.auth0.access_token");
        verify(storage).remove("com.auth0.refresh_token");
        verify(storage).remove("com.auth0.token_type");
        verify(storage).remove("com.auth0.expires_at");
        verify(storage).remove("com.auth0.scope");
        verify(storage).remove("com.auth0.cache_expires_at");
        verifyNoMoreInteractions(storage);
    }

    @Test
    public void shouldHaveCredentialsWhenTokenHasNotExpired() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn(null);
        assertThat(manager.hasValidCredentials(), is(true));
        assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), is(true));

        when(storage.retrieveString("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        assertThat(manager.hasValidCredentials(), is(true));
        assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), is(true));
    }

    @Test
    public void shouldNotHaveCredentialsWhenTokenHasExpiredAndNoRefreshTokenIsAvailable() {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn(null);
        assertFalse(manager.hasValidCredentials());

        when(storage.retrieveString("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        assertFalse(manager.hasValidCredentials());
    }

    @Test
    public void shouldNotHaveCredentialsWhenAccessTokenWillExpireAndNoRefreshTokenIsAvailable() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null);

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");

        assertFalse(manager.hasValidCredentials(ONE_HOUR_SECONDS));
    }

    @Test
    public void shouldHaveCredentialsWhenTokenHasExpiredButRefreshTokenIsAvailable() {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn("refreshToken");

        when(storage.retrieveString("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieveString("com.auth0.access_token")).thenReturn(null);
        assertThat(manager.hasValidCredentials(), is(true));

        when(storage.retrieveString("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        assertThat(manager.hasValidCredentials(), is(true));
    }

    @Test
    public void shouldNotHaveCredentialsWhenAccessTokenAndIdTokenAreMissing() {
        when(storage.retrieveString("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.access_token")).thenReturn(null);

        assertFalse(manager.hasValidCredentials());
    }

    @Test
    public void shouldRecreateTheCredentials() {
        CredentialsManager credentialsManager = new CredentialsManager(client, storage);
        Date now = new Date();
        final Credentials credentials = credentialsManager.recreateCredentials("idTOKEN", "accessTOKEN", "tokenTYPE", "refreshTOKEN", now, "openid profile");
        assertThat(credentials, is(notNullValue()));
        assertThat(credentials.getIdToken(), is("idTOKEN"));
        assertThat(credentials.getAccessToken(), is("accessTOKEN"));
        assertThat(credentials.getType(), is("tokenTYPE"));
        assertThat(credentials.getRefreshToken(), is("refreshTOKEN"));
        assertThat(credentials.getExpiresAt(), is(now));
        assertThat(credentials.getScope(), is("openid profile"));
    }

    @Test
    public void shouldUseCustomClock() {
        CredentialsManager manager = new CredentialsManager(client, storage);

        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.cache_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveString("com.auth0.refresh_token")).thenReturn(null);
        when(storage.retrieveString("com.auth0.access_token")).thenReturn("accessToken");
        assertThat(manager.hasValidCredentials(), is(false));

        //now, update the clock and retry
        manager.setClock(new Clock() {
            @Override
            public long getCurrentTimeMillis() {
                return CredentialsMock.CURRENT_TIME_MS - 1000;
            }
        });
        assertThat(manager.hasValidCredentials(), is(true));
    }

    private void prepareJwtDecoderMock(@Nullable Date expiresAt) {
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(expiresAt);
        when(jwtDecoder.decode("idToken")).thenReturn(jwtMock);
    }
}
