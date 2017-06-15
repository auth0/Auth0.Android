package com.auth0.android.authentication.storage;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.result.Credentials;

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
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class CredentialsManagerTest {

    @Mock
    private AuthenticationAPIClient client;
    @Mock
    private Storage storage;
    @Mock
    private BaseCallback<Credentials, CredentialsManagerException> callback;
    @Mock
    private ParameterizableRequest<Credentials, AuthenticationException> request;
    @Captor
    private ArgumentCaptor<Credentials> credentialsCaptor;
    @Captor
    private ArgumentCaptor<CredentialsManagerException> exceptionCaptor;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static final long CURRENT_TIME_MS = 999000000L;
    private CredentialsManager manager;
    @Captor
    private ArgumentCaptor<BaseCallback<Credentials, AuthenticationException>> requestCallbackCaptor;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        CredentialsManager credentialsManager = new CredentialsManager(client, storage);
        manager = spy(credentialsManager);
        doReturn(CURRENT_TIME_MS).when(manager).getCurrentTimeInMillis();
    }

    @Test
    public void shouldSaveCredentialsInStorage() throws Exception {
        Credentials credentials = new Credentials("idToken", "accessToken", "type", "refreshToken", 123456L);
        manager.setCredentials(credentials);

        verify(storage).store("com.auth0.id_token", "idToken");
        verify(storage).store("com.auth0.access_token", "accessToken");
        verify(storage).store("com.auth0.refresh_token", "refreshToken");
        verify(storage).store("com.auth0.token_type", "type");
        verify(storage).store("com.auth0.expires_in", "123456");
        long expirationTime = CURRENT_TIME_MS + (123456 * 1000);
        verify(storage).store("com.auth0.expiration_time", Long.toString(expirationTime));
    }

    @Test
    public void shouldThrowOnSetIfCredentialsDoesNotHaveIdTokenOrAccessToken() throws Exception {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid expires_in value and a valid access_token or id_token value.");

        Credentials credentials = new Credentials(null, null, "type", "refreshToken", 123456L);
        manager.setCredentials(credentials);
    }

    @Test
    public void shouldThrowOnSetIfCredentialsDoesNotHaveExpiresIn() throws Exception {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid expires_in value and a valid access_token or id_token value.");

        Credentials credentials = new Credentials("idToken", "accessToken", "type", "refreshToken", null);
        manager.setCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSetIfCredentialsHaveAccessTokenAndExpiresIn() throws Exception {
        Credentials credentials = new Credentials(null, "accessToken", "type", "refreshToken", 123456L);
        manager.setCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSetIfCredentialsHaveIdTokenAndExpiresIn() throws Exception {
        Credentials credentials = new Credentials("idToken", null, "type", "refreshToken", 123456L);
        manager.setCredentials(credentials);
    }

    @Test
    public void shouldFailOnGetCredentialsWhenNoAccessTokenOrIdTokenWasSaved() throws Exception {
        verifyNoMoreInteractions(client);

        when(storage.retrieve("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieve("com.auth0.access_token")).thenReturn(null);
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        String expirationTime = Long.toString(CURRENT_TIME_MS + (123456L * 1000));
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldFailOnGetCredentialsWhenNoExpiresInWasSaved() throws Exception {
        verifyNoMoreInteractions(client);

        when(storage.retrieve("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieve("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn(null);
        String expirationTime = Long.toString(CURRENT_TIME_MS + (123456L * 1000));
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldFailOnGetCredentialsWhenNoExpirationTimeWasSaved() throws Exception {
        verifyNoMoreInteractions(client);

        when(storage.retrieve("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieve("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(null);

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldFailOnGetCredentialsWhenExpiredAndNoRefreshTokenWasSaved() throws Exception {
        verifyNoMoreInteractions(client);

        when(storage.retrieve("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieve("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn(null);
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        String expirationTime = Long.toString(CURRENT_TIME_MS); //Same as current time --> expired
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Refresh Token available."));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorage() throws Exception {
        verifyNoMoreInteractions(client);

        when(storage.retrieve("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieve("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        String expirationTime = Long.toString(CURRENT_TIME_MS + (123456L * 1000));
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is("accessToken"));
        assertThat(retrievedCredentials.getIdToken(), is("idToken"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresIn(), is(123456L));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() throws Exception {
        verifyNoMoreInteractions(client);

        when(storage.retrieve("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieve("com.auth0.access_token")).thenReturn(null);
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        String expirationTime = Long.toString(CURRENT_TIME_MS + (123456L * 1000));
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is(nullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("idToken"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresIn(), is(123456L));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyAccessTokenIsAvailable() throws Exception {
        verifyNoMoreInteractions(client);

        when(storage.retrieve("com.auth0.id_token")).thenReturn(null);
        when(storage.retrieve("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        String expirationTime = Long.toString(CURRENT_TIME_MS + (123456L * 1000));
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is("accessToken"));
        assertThat(retrievedCredentials.getIdToken(), is(nullValue()));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresIn(), is(123456L));
    }

    @Test
    public void shouldGetAndSuccessfullyRenewExpiredCredentials() throws Exception {
        when(storage.retrieve("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieve("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        String expirationTime = Long.toString(CURRENT_TIME_MS); //Same as current time --> expired
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(callback);
        verify(request).start(requestCallbackCaptor.capture());

        //Trigger success
        Credentials renewedCredentials = mock(Credentials.class);
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());

        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials, is(renewedCredentials));
    }

    @Test
    public void shouldGetAndFailToRenewExpiredCredentials() throws Exception {
        when(storage.retrieve("com.auth0.id_token")).thenReturn("idToken");
        when(storage.retrieve("com.auth0.access_token")).thenReturn("accessToken");
        when(storage.retrieve("com.auth0.refresh_token")).thenReturn("refreshToken");
        when(storage.retrieve("com.auth0.token_type")).thenReturn("type");
        when(storage.retrieve("com.auth0.expires_in")).thenReturn("123456");
        String expirationTime = Long.toString(CURRENT_TIME_MS); //Same as current time --> expired
        when(storage.retrieve("com.auth0.expiration_time")).thenReturn(expirationTime);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(callback);
        verify(request).start(requestCallbackCaptor.capture());

        //Trigger failure
        AuthenticationException authenticationException = mock(AuthenticationException.class);
        requestCallbackCaptor.getValue().onFailure(authenticationException);
        verify(callback).onFailure(exceptionCaptor.capture());

        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCause(), Is.<Throwable>is(authenticationException));
        assertThat(exception.getMessage(), is("An error occurred while trying to use the refresh_token to renew the credentials."));
    }
}