package com.auth0.android.authentication.storage;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Base64;

import androidx.annotation.Nullable;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.JWT;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.request.internal.GsonProvider;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.auth0.android.util.Clock;
import com.google.gson.Gson;

import org.hamcrest.core.Is;
import org.hamcrest.core.IsInstanceOf;
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
import org.robolectric.util.ReflectionHelpers;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
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
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class SecureCredentialsManagerTest {

    private static final long ONE_HOUR_SECONDS = 60 * 60;

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
    @Mock
    private JWTDecoder jwtDecoder;
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

    private SecureCredentialsManager manager;
    private Gson gson;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        Activity activity = Robolectric.buildActivity(Activity.class).create().start().resume().get();
        Activity activityContext = spy(activity);
        KeyguardManager kManager = mock(KeyguardManager.class);
        when(activityContext.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kManager);

        SecureCredentialsManager secureCredentialsManager = new SecureCredentialsManager(client, storage, crypto, jwtDecoder);
        manager = spy(secureCredentialsManager);
        doReturn(CredentialsMock.CURRENT_TIME_MS).when(manager).getCurrentTimeInMillis();
        gson = GsonProvider.buildGson();
    }

    @Test
    public void shouldCreateAManagerInstance() {
        Context context = Robolectric.buildActivity(Activity.class).create().start().resume().get();
        AuthenticationAPIClient apiClient = new AuthenticationAPIClient(new Auth0("clientId", "domain"));
        Storage storage = new SharedPreferencesStorage(context);
        final SecureCredentialsManager manager = new SecureCredentialsManager(context, apiClient, storage);
        assertThat(manager, is(notNullValue()));
    }

    /*
     * SAVE Credentials tests
     */

    @Test
    public void shouldSaveRefreshableCredentialsInStorage() {
        long sharedExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(sharedExpirationTime), "scope");
        String json = gson.toJson(credentials);
        prepareJwtDecoderMock(new Date(sharedExpirationTime));
        when(crypto.encrypt(json.getBytes())).thenReturn(json.getBytes());

        manager.saveCredentials(credentials);

        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", sharedExpirationTime);
        verify(storage).store("com.auth0.credentials_access_token_expires_at", sharedExpirationTime);
        verify(storage).store("com.auth0.credentials_can_refresh", true);
        verify(storage).store("com.auth0.manager_key_alias", SecureCredentialsManager.KEY_ALIAS);
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
        assertThat(storedCredentials.getExpiresAt().getTime(), is(sharedExpirationTime));
        assertThat(storedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldSaveRefreshableCredentialsUsingAccessTokenExpForCacheExpirationInStorage() {
        long accessTokenExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock(null, "accessToken", "type", "refreshToken", new Date(accessTokenExpirationTime), "scope");
        String json = gson.toJson(credentials);
        prepareJwtDecoderMock(new Date(accessTokenExpirationTime));
        when(crypto.encrypt(json.getBytes())).thenReturn(json.getBytes());

        manager.saveCredentials(credentials);

        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", accessTokenExpirationTime);
        verify(storage).store("com.auth0.credentials_access_token_expires_at", accessTokenExpirationTime);
        verify(storage).store("com.auth0.credentials_can_refresh", true);
        verify(storage).store("com.auth0.manager_key_alias", SecureCredentialsManager.KEY_ALIAS);
        verifyNoMoreInteractions(storage);
        final String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials storedCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(storedCredentials.getAccessToken(), is("accessToken"));
        assertThat(storedCredentials.getIdToken(), is(nullValue()));
        assertThat(storedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(storedCredentials.getType(), is("type"));
        assertThat(storedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(storedCredentials.getExpiresAt().getTime(), is(accessTokenExpirationTime));
        assertThat(storedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldSaveRefreshableCredentialsUsingIdTokenExpForCacheExpirationInStorage() {
        long accessTokenExpirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        long idTokenExpirationTime = CredentialsMock.CURRENT_TIME_MS + 2000 * 1000;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(accessTokenExpirationTime), "scope");
        String json = gson.toJson(credentials);
        prepareJwtDecoderMock(new Date(idTokenExpirationTime));
        when(crypto.encrypt(json.getBytes())).thenReturn(json.getBytes());

        manager.saveCredentials(credentials);

        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", idTokenExpirationTime);
        verify(storage).store("com.auth0.credentials_access_token_expires_at", accessTokenExpirationTime);
        verify(storage).store("com.auth0.credentials_can_refresh", true);
        verify(storage).store("com.auth0.manager_key_alias", SecureCredentialsManager.KEY_ALIAS);
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
        assertThat(storedCredentials.getExpiresAt().getTime(), is(accessTokenExpirationTime));
        assertThat(storedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldSaveNonRefreshableCredentialsInStorage() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", null, new Date(expirationTime), "scope");
        String json = gson.toJson(credentials);
        prepareJwtDecoderMock(new Date(expirationTime));
        when(crypto.encrypt(json.getBytes())).thenReturn(json.getBytes());

        manager.saveCredentials(credentials);

        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", expirationTime);
        verify(storage).store("com.auth0.credentials_access_token_expires_at", expirationTime);
        verify(storage).store("com.auth0.credentials_can_refresh", false);
        verify(storage).store("com.auth0.manager_key_alias", SecureCredentialsManager.KEY_ALIAS);
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
    public void shouldClearStoredCredentialsAndThrowOnSaveOnCryptoException() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(expirationTime), "scope");
        prepareJwtDecoderMock(new Date(expirationTime));
        when(crypto.encrypt(any(byte[].class))).thenThrow(new CryptoException(null, null));

        CredentialsManagerException exception = null;
        try {
            manager.saveCredentials(credentials);
        } catch (CredentialsManagerException e) {
            exception = e;
        }
        assertThat(exception, is(notNullValue()));
        assertThat(exception.isDeviceIncompatible(), is(false));
        assertThat(exception.getMessage(), is("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Please, try saving the credentials again."));

        verify(storage).remove("com.auth0.credentials");
        verify(storage).remove("com.auth0.credentials_expires_at");
        verify(storage).remove("com.auth0.credentials_can_refresh");
    }

    @Test
    public void shouldThrowOnSaveOnIncompatibleDeviceException() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(expirationTime), "scope");
        prepareJwtDecoderMock(new Date(expirationTime));
        when(crypto.encrypt(any(byte[].class))).thenThrow(new IncompatibleDeviceException(null));

        CredentialsManagerException exception = null;
        try {
            manager.saveCredentials(credentials);
        } catch (CredentialsManagerException e) {
            exception = e;
        }
        assertThat(exception, is(notNullValue()));
        assertThat(exception.isDeviceIncompatible(), is(true));
        assertThat(exception.getMessage(), is("This device is not compatible with the SecureCredentialsManager class."));
    }

    @Test
    public void shouldThrowOnSaveIfCredentialsDoesNotHaveIdTokenOrAccessToken() {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.");

        Credentials credentials = new CredentialsMock(null, null, "type", "refreshToken", ONE_HOUR_SECONDS);
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldThrowOnSaveIfCredentialsDoesNotHaveExpiresAt() {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("Credentials must have a valid date of expiration and a valid access_token or id_token value.");

        Date date = null;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope");
        prepareJwtDecoderMock(new Date());
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSaveIfCredentialsHaveAccessTokenAndExpiresIn() {
        Credentials credentials = new CredentialsMock(null, "accessToken", "type", "refreshToken", ONE_HOUR_SECONDS);
        when(crypto.encrypt(any(byte[].class))).thenReturn(new byte[]{12, 34, 56, 78});
        manager.saveCredentials(credentials);
    }

    @Test
    public void shouldNotThrowOnSaveIfCredentialsHaveIdTokenAndExpiresIn() {
        Credentials credentials = new CredentialsMock("idToken", null, "type", "refreshToken", ONE_HOUR_SECONDS);
        prepareJwtDecoderMock(new Date());
        when(crypto.encrypt(any(byte[].class))).thenReturn(new byte[]{12, 34, 56, 78});
        manager.saveCredentials(credentials);
    }

    /*
     * GET Credentials tests
     */

    @Test
    public void shouldClearStoredCredentialsAndFailOnGetCredentialsWhenCryptoExceptionIsThrown() {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        String storedJson = insertTestCredentials(true, true, true, expiresAt);
        when(crypto.decrypt(storedJson.getBytes())).thenThrow(new CryptoException(null, null));
        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCause(), IsInstanceOf.<Throwable>instanceOf(CryptoException.class));
        assertThat(exception.getMessage(), is("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. " +
                "Any previously stored content is now lost. Please, try saving the credentials again."));


        verify(storage).remove("com.auth0.credentials");
        verify(storage).remove("com.auth0.credentials_expires_at");
        verify(storage).remove("com.auth0.credentials_can_refresh");
    }

    @Test
    public void shouldFailOnGetCredentialsWhenIncompatibleDeviceExceptionIsThrown() {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        String storedJson = insertTestCredentials(true, true, true, expiresAt);
        when(crypto.decrypt(storedJson.getBytes())).thenThrow(new IncompatibleDeviceException(null));
        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCause(), IsInstanceOf.<Throwable>instanceOf(IncompatibleDeviceException.class));
        assertThat(exception.getMessage(), is("This device is not compatible with the SecureCredentialsManager class."));

        verify(storage, never()).remove("com.auth0.credentials");
        verify(storage, never()).remove("com.auth0.credentials_expires_at");
        verify(storage, never()).remove("com.auth0.credentials_can_refresh");
    }

    @Test
    public void shouldFailOnGetCredentialsWhenNoAccessTokenOrIdTokenWasSaved() {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        insertTestCredentials(false, false, true, expiresAt);
        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldFailOnGetCredentialsWhenExpiredAndNoRefreshTokenWasSaved() {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS); //Same as current time --> expired
        insertTestCredentials(true, true, false, expiresAt);
        manager.getCredentials(callback);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));
    }

    @Test
    public void shouldGetNonExpiredCredentialsFromStorage() {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000);
        insertTestCredentials(true, true, true, expiresAt);

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
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyIdTokenIsAvailable() {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000);
        insertTestCredentials(true, false, true, expiresAt);


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
    public void shouldGetNonExpiredCredentialsFromStorageWhenOnlyAccessTokenIsAvailable() {
        verifyNoMoreInteractions(client);

        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + ONE_HOUR_SECONDS * 1000);
        insertTestCredentials(false, true, true, expiresAt);

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

    @Test
    public void shouldRenewCredentialsWithMinTtl() {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS); // expired credentials
        insertTestCredentials(false, true, true, expiresAt);

        Date newDate = new Date(CredentialsMock.CURRENT_TIME_MS + 61 * 1000); // new token expires in minTTL + 1 seconds
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(null, 60, callback); // minTTL of 1 minute
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        // Trigger success
        Credentials expectedCredentials = new Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope");
        String expectedJson = gson.toJson(expectedCredentials);
        when(crypto.encrypt(expectedJson.getBytes())).thenReturn(expectedJson.getBytes());
        requestCallbackCaptor.getValue().onSuccess(expectedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_can_refresh", true);
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

        // Verify the credentials are property stored
        String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials renewedStoredCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(renewedStoredCredentials.getIdToken(), is("newId"));
        assertThat(renewedStoredCredentials.getAccessToken(), is("newAccess"));
        assertThat(renewedStoredCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(renewedStoredCredentials.getType(), is("newType"));
        assertThat(renewedStoredCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(renewedStoredCredentials.getExpiresAt().getTime(), is(newDate.getTime()));
        assertThat(renewedStoredCredentials.getScope(), is("newScope"));
    }

    @Test
    public void shouldGetAndFailToRenewExpiredCredentialsWhenReceivedTokenHasLowerTtl() {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS); // expired credentials
        insertTestCredentials(false, true, true, expiresAt);

        Date newDate = new Date(CredentialsMock.CURRENT_TIME_MS + 59 * 1000); // new token expires in minTTL - 1 seconds
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(null, 60, callback); // minTTL of 1 minute
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        // Trigger failure
        Credentials expectedCredentials = new Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope");
        String expectedJson = gson.toJson(expectedCredentials);
        when(crypto.encrypt(expectedJson.getBytes())).thenReturn(expectedJson.getBytes());
        requestCallbackCaptor.getValue().onSuccess(expectedCredentials);

        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("The lifetime of the renewed Access Token (1) is less than the minTTL requested (60). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL."));

        verify(storage, never()).store(eq("com.auth0.credentials"), anyString());
        verify(storage, never()).store(eq("com.auth0.credentials_expires_at"), anyLong());
        verify(storage, never()).store(eq("com.auth0.credentials_can_refresh"), anyBoolean());
        verify(storage, never()).remove(anyString());
    }

    @Test
    public void shouldRenewCredentialsWhenScopeHasChanged() {
        Date expiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS); // non expired credentials
        insertTestCredentials(false, true, true, expiresAt); // "scope" is set

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS + ONE_HOUR_SECONDS * 1000);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials("different scope", 0, callback);  // minTTL of 0 seconds (default)
        verify(request).addParameter(eq("scope"), eq("different scope"));
        verify(request).start(requestCallbackCaptor.capture());

        // Trigger success
        Credentials expectedCredentials = new Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope");
        String expectedJson = gson.toJson(expectedCredentials);
        when(crypto.encrypt(expectedJson.getBytes())).thenReturn(expectedJson.getBytes());
        requestCallbackCaptor.getValue().onSuccess(expectedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_can_refresh", true);
        verify(storage, never()).remove(anyString());

        // Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("different scope"));

        // Verify the credentials are property stored
        String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials renewedStoredCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(renewedStoredCredentials.getIdToken(), is("newId"));
        assertThat(renewedStoredCredentials.getAccessToken(), is("newAccess"));
        assertThat(renewedStoredCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(renewedStoredCredentials.getType(), is("newType"));
        assertThat(renewedStoredCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(renewedStoredCredentials.getExpiresAt().getTime(), is(newDate.getTime()));
        assertThat(renewedStoredCredentials.getScope(), is("different scope"));
    }

    @Test
    public void shouldRenewExpiredCredentialsWhenScopeHasChanged() {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS); // current time means expired credentials
        insertTestCredentials(false, true, true, expiresAt);

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials("different scope", 0, callback);  // minTTL of 0 seconds (default)
        verify(request).addParameter(eq("scope"), eq("different scope"));
        verify(request).start(requestCallbackCaptor.capture());

        // Trigger success
        Credentials expectedCredentials = new Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "different scope");
        String expectedJson = gson.toJson(expectedCredentials);
        when(crypto.encrypt(expectedJson.getBytes())).thenReturn(expectedJson.getBytes());
        requestCallbackCaptor.getValue().onSuccess(expectedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_access_token_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_can_refresh", true);
        verify(storage, never()).remove(anyString());

        // Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("different scope"));

        // Verify the credentials are property stored
        String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials renewedStoredCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(renewedStoredCredentials.getIdToken(), is("newId"));
        assertThat(renewedStoredCredentials.getAccessToken(), is("newAccess"));
        assertThat(renewedStoredCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(renewedStoredCredentials.getType(), is("newType"));
        assertThat(renewedStoredCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(renewedStoredCredentials.getExpiresAt().getTime(), is(newDate.getTime()));
        assertThat(renewedStoredCredentials.getScope(), is("different scope"));
    }

    @Test
    public void shouldNotHaveCredentialsWhenAccessTokenWillExpireAndNoRefreshTokenIsAvailable() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveLong("com.auth0.credentials_access_token_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");

        assertFalse(manager.hasValidCredentials(ONE_HOUR_SECONDS));
    }

    @Test
    public void shouldGetAndSuccessfullyRenewExpiredCredentials() {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS); // current time means expired credentials
        insertTestCredentials(false, true, true, expiresAt);

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(callback);
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        // Trigger success
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", null, newDate, "newScope");
        Credentials expectedCredentials = new Credentials("newId", "newAccess", "newType", "refreshToken", newDate, "newScope");
        String expectedJson = gson.toJson(expectedCredentials);
        when(crypto.encrypt(expectedJson.getBytes())).thenReturn(expectedJson.getBytes());
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_can_refresh", true);
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

        // Verify the credentials are property stored
        String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials renewedStoredCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(renewedStoredCredentials.getIdToken(), is("newId"));
        assertThat(renewedStoredCredentials.getAccessToken(), is("newAccess"));
        assertThat(renewedStoredCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(renewedStoredCredentials.getType(), is("newType"));
        assertThat(renewedStoredCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(renewedStoredCredentials.getExpiresAt().getTime(), is(newDate.getTime()));
        assertThat(renewedStoredCredentials.getScope(), is("newScope"));
    }

    @Test
    public void shouldGetAndSuccessfullyRenewExpiredCredentialsWithRefreshTokenRotation() {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS);
        insertTestCredentials(false, true, true, expiresAt);

        Date newDate = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(newDate);
        when(jwtDecoder.decode("newId")).thenReturn(jwtMock);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(callback);
        verify(request, never()).addParameter(eq("scope"), anyString());
        verify(request).start(requestCallbackCaptor.capture());

        //Trigger success
        Credentials renewedCredentials = new Credentials("newId", "newAccess", "newType", "rotatedRefreshToken", newDate, "newScope");
        String expectedJson = gson.toJson(renewedCredentials);
        when(crypto.encrypt(expectedJson.getBytes())).thenReturn(expectedJson.getBytes());
        requestCallbackCaptor.getValue().onSuccess(renewedCredentials);
        verify(callback).onSuccess(credentialsCaptor.capture());
        verify(storage).store(eq("com.auth0.credentials"), stringCaptor.capture());
        verify(storage).store("com.auth0.credentials_expires_at", newDate.getTime());
        verify(storage).store("com.auth0.credentials_can_refresh", true);
        verify(storage, never()).remove(anyString());

        // Verify the returned credentials are the latest
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getIdToken(), is("newId"));
        assertThat(retrievedCredentials.getAccessToken(), is("newAccess"));
        assertThat(retrievedCredentials.getType(), is("newType"));
        assertThat(retrievedCredentials.getRefreshToken(), is("rotatedRefreshToken"));
        assertThat(retrievedCredentials.getExpiresAt(), is(newDate));
        assertThat(retrievedCredentials.getScope(), is("newScope"));

        // Verify the credentials are property stored
        String encodedJson = stringCaptor.getValue();
        assertThat(encodedJson, is(notNullValue()));
        final byte[] decoded = Base64.decode(encodedJson, Base64.DEFAULT);
        Credentials renewedStoredCredentials = gson.fromJson(new String(decoded), Credentials.class);
        assertThat(renewedStoredCredentials.getIdToken(), is("newId"));
        assertThat(renewedStoredCredentials.getAccessToken(), is("newAccess"));
        assertThat(renewedStoredCredentials.getRefreshToken(), is("rotatedRefreshToken"));
        assertThat(renewedStoredCredentials.getType(), is("newType"));
        assertThat(renewedStoredCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(renewedStoredCredentials.getExpiresAt().getTime(), is(newDate.getTime()));
        assertThat(renewedStoredCredentials.getScope(), is("newScope"));
    }

    @Test
    public void shouldGetAndFailToRenewExpiredCredentials() {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS);
        insertTestCredentials(false, true, true, expiresAt);
        when(client.renewAuth("refreshToken")).thenReturn(request);

        manager.getCredentials(callback);
        verify(request).start(requestCallbackCaptor.capture());

        //Trigger failure
        AuthenticationException authenticationException = mock(AuthenticationException.class);
        requestCallbackCaptor.getValue().onFailure(authenticationException);
        verify(callback).onFailure(exceptionCaptor.capture());
        verify(storage, never()).store(anyString(), anyLong());
        verify(storage, never()).store(anyString(), anyInt());
        verify(storage, never()).store(anyString(), anyString());
        verify(storage, never()).store(anyString(), anyBoolean());
        verify(storage, never()).remove(anyString());

        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCause(), Is.<Throwable>is(authenticationException));
        assertThat(exception.getMessage(), is("An error occurred while trying to use the Refresh Token to renew the Credentials."));
    }

    /*
     * CLEAR Credentials tests
     */

    @Test
    public void shouldClearCredentials() {
        manager.clearCredentials();

        verify(storage).remove("com.auth0.credentials");
        verify(storage).remove("com.auth0.credentials_expires_at");
        verify(storage).remove("com.auth0.credentials_access_token_expires_at");
        verify(storage).remove("com.auth0.credentials_can_refresh");
        verify(storage).remove("com.auth0.manager_key_alias");
        verifyNoMoreInteractions(storage);
    }

    /*
     * HAS Credentials tests
     */

    @Test
    public void shouldPreventLoggingOutUsersWhenAccessTokenExpiresAtWasNotSaved() {
        long cacheExpiresAt = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(cacheExpiresAt);
        when(storage.retrieveLong("com.auth0.credentials_access_token_expires_at")).thenReturn(null);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(SecureCredentialsManager.KEY_ALIAS);
        assertThat(manager.hasValidCredentials(), is(true));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        assertThat(manager.hasValidCredentials(), is(true));
    }

    @Test
    public void shouldHaveCredentialsWhenTokenHasNotExpired() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(SecureCredentialsManager.KEY_ALIAS);
        assertThat(manager.hasValidCredentials(), is(true));
        assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), is(true));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        assertThat(manager.hasValidCredentials(), is(true));
        assertThat(manager.hasValidCredentials(ONE_HOUR_SECONDS - 1), is(true));
    }

    @Test
    public void shouldNotHaveCredentialsWhenTokenHasExpiredAndNoRefreshTokenIsAvailable() {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(SecureCredentialsManager.KEY_ALIAS);
        assertThat(manager.hasValidCredentials(), is(false));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        assertThat(manager.hasValidCredentials(), is(false));
    }

    @Test
    public void shouldHaveCredentialsWhenTokenHasExpiredButRefreshTokenIsAvailable() {
        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(true);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\", \"refresh_token\":\"refreshToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(SecureCredentialsManager.KEY_ALIAS);
        assertThat(manager.hasValidCredentials(), is(true));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\", \"refresh_token\":\"refreshToken\"}");
        assertThat(manager.hasValidCredentials(), is(true));
    }

    @Test
    public void shouldNotHaveCredentialsWhenAccessTokenAndIdTokenAreMissing() {
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"token_type\":\"type\", \"refresh_token\":\"refreshToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(SecureCredentialsManager.KEY_ALIAS);

        assertFalse(manager.hasValidCredentials());
    }

    @Test
    public void shouldNotHaveCredentialsWhenTheAliasUsedHasNotBeenMigratedYet() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn("old_alias");
        assertThat(manager.hasValidCredentials(), is(false));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        assertThat(manager.hasValidCredentials(), is(false));
    }

    @Test
    public void shouldNotHaveCredentialsWhenTheAliasUsedHasNotBeenSetYet() {
        long expirationTime = CredentialsMock.ONE_HOUR_AHEAD_MS;
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"id_token\":\"idToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(null);
        assertThat(manager.hasValidCredentials(), is(false));

        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        assertThat(manager.hasValidCredentials(), is(false));
    }

    /*
     * Authentication tests
     */

    @Test
    public void shouldThrowOnInvalidAuthenticationRequestCode() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Request code must be a value between 1 and 255.");
        Activity activity = Robolectric.buildActivity(Activity.class).create().start().resume().get();

        manager.requireAuthentication(activity, 256, null, null);
    }

    @Test
    @Config(sdk = 21)
    public void shouldNotRequireAuthenticationIfAPI21AndLockScreenDisabled() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 21);
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());

        //Set LockScreen as Disabled
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(false);
        when(kService.createConfirmDeviceCredentialIntent("title", "description")).thenReturn(null);

        boolean willAskAuthentication = manager.requireAuthentication(activity, 123, "title", "description");

        assertThat(willAskAuthentication, is(false));
    }

    @Test
    @Config(sdk = 23)
    public void shouldNotRequireAuthenticationIfAPI23AndLockScreenDisabled() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 23);
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());

        //Set LockScreen as Disabled
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isDeviceSecure()).thenReturn(false);
        when(kService.createConfirmDeviceCredentialIntent("title", "description")).thenReturn(null);

        boolean willAskAuthentication = manager.requireAuthentication(activity, 123, "title", "description");

        assertThat(willAskAuthentication, is(false));
    }

    @Test
    @Config(sdk = 21)
    public void shouldRequireAuthenticationIfAPI21AndLockScreenEnabled() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 21);
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());

        //Set LockScreen as Enabled
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(true);
        when(kService.createConfirmDeviceCredentialIntent("title", "description")).thenReturn(new Intent());

        boolean willAskAuthentication = manager.requireAuthentication(activity, 123, "title", "description");

        assertThat(willAskAuthentication, is(true));
    }

    @Test
    @Config(sdk = 23)
    public void shouldRequireAuthenticationIfAPI23AndLockScreenEnabled() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 23);
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());

        //Set LockScreen as Enabled
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isDeviceSecure()).thenReturn(true);
        when(kService.createConfirmDeviceCredentialIntent("title", "description")).thenReturn(new Intent());

        boolean willAskAuthentication = manager.requireAuthentication(activity, 123, "title", "description");

        assertThat(willAskAuthentication, is(true));
    }

    @Test
    public void shouldGetCredentialsAfterAuthentication() {
        Date expiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        insertTestCredentials(true, true, false, expiresAt);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());

        //Require authentication
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(true);
        Intent confirmCredentialsIntent = mock(Intent.class);
        when(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription")).thenReturn(confirmCredentialsIntent);
        boolean willRequireAuthentication = manager.requireAuthentication(activity, 123, "theTitle", "theDescription");
        assertThat(willRequireAuthentication, is(true));

        manager.getCredentials(callback);

        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivityForResult(intentCaptor.capture(), eq(123));
        assertThat(intentCaptor.getValue(), is(confirmCredentialsIntent));


        //Continue after successful authentication
        final boolean processed = manager.checkAuthenticationResult(123, Activity.RESULT_OK);
        assertThat(processed, is(true));

        verify(callback).onSuccess(credentialsCaptor.capture());
        Credentials retrievedCredentials = credentialsCaptor.getValue();
        assertThat(retrievedCredentials, is(notNullValue()));
        assertThat(retrievedCredentials.getAccessToken(), is("accessToken"));
        assertThat(retrievedCredentials.getIdToken(), is("idToken"));
        assertThat(retrievedCredentials.getRefreshToken(), is(nullValue()));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expiresAt.getTime()));
        assertThat(retrievedCredentials.getScope(), is("scope"));

        //A second call to checkAuthenticationResult should fail as callback is set to null
        final boolean retryCheck = manager.checkAuthenticationResult(123, Activity.RESULT_OK);
        assertThat(retryCheck, is(false));
    }

    @Test
    public void shouldNotGetCredentialsWhenCredentialsHaveExpired() {
        Date credentialsExpiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        Date storedExpiresAt = new Date(CredentialsMock.CURRENT_TIME_MS - ONE_HOUR_SECONDS * 1000);
        insertTestCredentials(true, true, false, credentialsExpiresAt);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(storedExpiresAt.getTime());

        //Require authentication
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(true);
        Intent confirmCredentialsIntent = mock(Intent.class);
        when(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription")).thenReturn(confirmCredentialsIntent);
        boolean willRequireAuthentication = manager.requireAuthentication(activity, 123, "theTitle", "theDescription");
        assertThat(willRequireAuthentication, is(true));

        manager.getCredentials(callback);

        //Should fail because of expired credentials
        verify(callback).onFailure(exceptionCaptor.capture());
        CredentialsManagerException exception = exceptionCaptor.getValue();
        assertThat(exception, is(notNullValue()));
        assertThat(exception.getMessage(), is("No Credentials were previously set."));

        //A second call to checkAuthenticationResult should fail as callback is set to null
        final boolean retryCheck = manager.checkAuthenticationResult(123, Activity.RESULT_OK);
        assertThat(retryCheck, is(false));
    }

    @Test
    public void shouldNotGetCredentialsAfterCanceledAuthentication() {
        Date expiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        insertTestCredentials(true, true, false, expiresAt);

        //Require authentication
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(true);
        Intent confirmCredentialsIntent = mock(Intent.class);
        when(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription")).thenReturn(confirmCredentialsIntent);
        boolean willRequireAuthentication = manager.requireAuthentication(activity, 123, "theTitle", "theDescription");
        assertThat(willRequireAuthentication, is(true));

        manager.getCredentials(callback);

        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivityForResult(intentCaptor.capture(), eq(123));
        assertThat(intentCaptor.getValue(), is(confirmCredentialsIntent));


        //Continue after canceled authentication
        final boolean processed = manager.checkAuthenticationResult(123, Activity.RESULT_CANCELED);
        assertThat(processed, is(true));

        verify(callback, never()).onSuccess(any(Credentials.class));
        verify(callback).onFailure(exceptionCaptor.capture());

        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue().getMessage(), is("The user didn't pass the authentication challenge."));
    }

    @Test
    public void shouldNotGetCredentialsOnDifferentAuthenticationRequestCode() {
        Date expiresAt = new Date(CredentialsMock.ONE_HOUR_AHEAD_MS);
        insertTestCredentials(true, true, false, expiresAt);

        //Require authentication
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(true);
        Intent confirmCredentialsIntent = mock(Intent.class);
        when(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription")).thenReturn(confirmCredentialsIntent);
        boolean willRequireAuthentication = manager.requireAuthentication(activity, 100, "theTitle", "theDescription");
        assertThat(willRequireAuthentication, is(true));

        manager.getCredentials(callback);

        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivityForResult(intentCaptor.capture(), eq(100));
        assertThat(intentCaptor.getValue(), is(confirmCredentialsIntent));


        //Continue after successful authentication
        verifyNoMoreInteractions(callback);
        final boolean processed = manager.checkAuthenticationResult(123, Activity.RESULT_OK);
        assertThat(processed, is(false));

    }

    /*
     * Custom Clock
     */

    @Test
    public void shouldUseCustomClock() {
        SecureCredentialsManager manager = new SecureCredentialsManager(client, storage, crypto, jwtDecoder);

        long expirationTime = CredentialsMock.CURRENT_TIME_MS; //Same as current time --> expired
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expirationTime);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);
        when(storage.retrieveString("com.auth0.credentials")).thenReturn("{\"access_token\":\"accessToken\"}");
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(SecureCredentialsManager.KEY_ALIAS);
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

    /*
     * Helper methods
     */

    /**
     * Used to simplify the tests length
     */
    private String insertTestCredentials(boolean hasIdToken, boolean hasAccessToken, boolean hasRefreshToken, Date willExpireAt) {
        Credentials storedCredentials = new Credentials(hasIdToken ? "idToken" : null, hasAccessToken ? "accessToken" : null, "type",
                hasRefreshToken ? "refreshToken" : null, willExpireAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(willExpireAt != null ? willExpireAt.getTime() : null);
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(hasRefreshToken);
        when(storage.retrieveString("com.auth0.manager_key_alias")).thenReturn(SecureCredentialsManager.KEY_ALIAS);
        return storedJson;
    }

    private void prepareJwtDecoderMock(@Nullable Date expiresAt) {
        JWT jwtMock = mock(JWT.class);
        when(jwtMock.getExpiresAt()).thenReturn(expiresAt);
        when(jwtDecoder.decode("idToken")).thenReturn(jwtMock);
    }
}