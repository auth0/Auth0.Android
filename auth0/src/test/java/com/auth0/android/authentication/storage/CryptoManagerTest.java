package com.auth0.android.authentication.storage;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.google.gson.Gson;

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
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Date;

import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class CryptoManagerTest {

    @Mock
    private AuthenticationAPIClient client;
    @Mock
    private Storage storage;
    @Mock
    private BaseCallback<Credentials, CredentialsManagerException> callback;
    @Mock
    private ParameterizableRequest<Credentials, AuthenticationException> request;
    @Mock
    private CryptoUtil crypto;
    @Captor
    private ArgumentCaptor<Credentials> credentialsCaptor;
    @Captor
    private ArgumentCaptor<CredentialsManagerException> exceptionCaptor;
    @Captor
    private ArgumentCaptor<String> stringCaptor;
    @Captor
    private ArgumentCaptor<BaseCallback<Credentials, AuthenticationException>> requestCallbackCaptor;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private CryptoManager manager;
    private Gson gson;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Activity activity = Robolectric.buildActivity(Activity.class).create().start().resume().get();
        Activity activityContext = spy(activity);
        KeyguardManager kManager = mock(KeyguardManager.class);
        when(activityContext.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kManager);

        CryptoManager cryptoManager = new CryptoManager(activityContext, client, storage, false, crypto);
        manager = spy(cryptoManager);
        doReturn(CredentialsMock.CURRENT_TIME_MS).when(manager).getCurrentTimeInMillis();
        gson = new Gson();
    }

    @Test
    public void shouldSaveRefreshableCredentialsInStorage() throws Exception {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS + 123456 * 1000;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(expirationTime), "scope");
        String json = gson.toJson(credentials);
        when(crypto.encrypt(json.getBytes())).thenReturn(json.getBytes());

        manager.saveCredentials(credentials);

        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", expirationTime);
        verify(storage).store("com.auth0.credentials_can_refresh", true);
        verifyNoMoreInteractions(storage);
        final String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials storedCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(storedCredentials.getAccessToken(), is("accessToken"));
        assertThat(storedCredentials.getIdToken(), is("idToken"));
        assertThat(storedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(storedCredentials.getType(), is("type"));
        assertThat(storedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(storedCredentials.getExpiresAt().getTime(), is(expirationTime));
        assertThat(storedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldSaveNonRefreshableCredentialsInStorage() throws Exception {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS + 123456 * 1000;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", null, new Date(expirationTime), "scope");
        String json = gson.toJson(credentials);
        when(crypto.encrypt(json.getBytes())).thenReturn(json.getBytes());

        manager.saveCredentials(credentials);

        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", expirationTime);
        verify(storage).store("com.auth0.credentials_can_refresh", false);
        verifyNoMoreInteractions(storage);
        final String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials storedCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(storedCredentials.getAccessToken(), is("accessToken"));
        assertThat(storedCredentials.getIdToken(), is("idToken"));
        assertThat(storedCredentials.getRefreshToken(), is(nullValue()));
        assertThat(storedCredentials.getType(), is("type"));
        assertThat(storedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(storedCredentials.getExpiresAt().getTime(), is(expirationTime));
        assertThat(storedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldThrowOnSetIfCredentialsDoesNotHaveIdTokenOrAccessToken() throws Exception {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.");

        Credentials credentials = new CredentialsMock(null, null, "type", "refreshToken", 123456L);
        manager.saveCredentials(credentials);
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void shouldThrowOnSetIfCredentialsDoesNotHaveExpiresAt() throws Exception {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.");

        Date date = null;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope");
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSetIfCredentialsHaveAccessTokenAndExpiresIn() throws Exception {
        Credentials credentials = new CredentialsMock(null, "accessToken", "type", "refreshToken", 123456L);
        when(crypto.encrypt(any(byte[].class))).thenReturn(new byte[]{12, 34, 56, 78});
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSetIfCredentialsHaveIdTokenAndExpiresIn() throws Exception {
        Credentials credentials = new CredentialsMock("idToken", null, "type", "refreshToken", 123456L);
        when(crypto.encrypt(any(byte[].class))).thenReturn(new byte[]{12, 34, 56, 78});
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldFailOnGetCredentialsWhenNoAccessTokenOrIdTokenWasSaved() throws Exception {
        verifyNoMoreInteractions(client);

        long expirationTime = CredentialsMock.CURRENT_TIME_MS + 123456L * 1000;
        Credentials storedCredentials = new Credentials(null, null, "type", "refreshToken", new Date(expirationTime), "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldFailOnGetCredentialsWhenNoExpirationTimeWasSaved() throws Exception {
        verifyNoMoreInteractions(client);

        Date expiresAt = null;
        Credentials storedCredentials = new Credentials("idToken", "accessToken", "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @SuppressWarnings("UnnecessaryLocalVariable")
    @Test
    public void shouldFailOnGetCredentialsWhenExpiredAndNoRefreshTokenWasSaved() throws Exception {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS); //Same as current time --> expired
        Credentials storedCredentials = new Credentials("idToken", "accessToken", "type", null, expiresAt, "scope");
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);

        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorage() throws Exception {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + 123456L * 1000);
        Credentials storedCredentials = new Credentials("idToken", "accessToken", "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is("accessToken"));
        assertThat(retrievedCredentials.getIdToken(), is("idToken"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expiresAt.getTime()));
        assertThat(retrievedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() throws Exception {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + 123456L * 1000);
        Credentials storedCredentials = new Credentials("idToken", null, "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is(nullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("idToken"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expiresAt.getTime()));
        assertThat(retrievedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyAccessTokenIsAvailable() throws Exception {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + 123456L * 1000);
        Credentials storedCredentials = new Credentials(null, "accessToken", "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);

        manager.getCredentials(callback);
        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();

        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is("accessToken"));
        assertThat(retrievedCredentials.getIdToken(), is(nullValue()));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expiresAt.getTime()));
        assertThat(retrievedCredentials.getScope(), is("scope"));
    }

    @SuppressWarnings("UnnecessaryLocalVariable")
    @Test
    public void shouldGetAndSuccessfullyRenewExpiredCredentials() throws Exception {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS);
        Credentials storedCredentials = new Credentials(null, "accessToken", "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(true);
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

    @SuppressWarnings("UnnecessaryLocalVariable")
    @Test
    public void shouldGetAndFailToRenewExpiredCredentials() throws Exception {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS);
        Credentials storedCredentials = new Credentials(null, "accessToken", "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(true);
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
        assertThat(exception.getMessage(), is("An error occurred while trying to use the Refresh Token to renew the Credentials."));
    }

    @Test
    public void shouldClearCredentials() throws Exception {
        manager.clearCredentials();

        verify(storage).remove("com.auth0.credentials");
        verify(storage).remove("com.auth0.credentials_expires_at");
        verify(storage).remove("com.auth0.credentials_can_refresh");
        verifyNoMoreInteractions(storage);
    }

    @Test
    public void shouldHaveCredentialsWhenTokenHasNotExpired() throws Exception {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS + 123456L * 1000;
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");
        assertThat(manager.hasValidCredentials(), is(true));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        assertThat(manager.hasValidCredentials(), is(true));
    }

    @Test
    public void shouldNotHaveCredentialsWhenTokenHasExpiredAndNoRefreshTokenIsAvailable() throws Exception {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");
        assertThat(manager.hasValidCredentials(), is(false));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        assertThat(manager.hasValidCredentials(), is(false));
    }

    @Test
    public void shouldHaveCredentialsWhenTokenHasExpiredButRefreshTokenIsAvailable() throws Exception {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(true);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\", \"refresh_token\":\"refreshToken\"}");
        assertThat(manager.hasValidCredentials(), is(true));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\", \"refresh_token\":\"refreshToken\"}");
        assertThat(manager.hasValidCredentials(), is(true));
    }

    @Test
    public void shouldNotHaveCredentialsWhenAccessTokenAndIdTokenAreMissing() throws Exception {
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"token_type\":\"type\", \"refresh_token\":\"refreshToken\"}");

        assertFalse(manager.hasValidCredentials());
    }
}