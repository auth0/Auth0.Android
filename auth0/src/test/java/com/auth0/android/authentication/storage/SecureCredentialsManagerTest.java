package com.auth0.android.authentication.storage;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import com.auth0.android.Auth0;
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
import org.robolectric.util.ReflectionHelpers;

import java.util.Date;

import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
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

@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class SecureCredentialsManagerTest {

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

    private SecureCredentialsManager manager;
    private Gson gson;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Activity activity = Robolectric.buildActivity(Activity.class).create().start().resume().get();
        Activity activityContext = spy(activity);
        KeyguardManager kManager = mock(KeyguardManager.class);
        when(activityContext.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kManager);

        SecureCredentialsManager secureCredentialsManager = new SecureCredentialsManager(client, storage, crypto);
        manager = spy(secureCredentialsManager);
        doReturn(CredentialsMock.CURRENT_TIME_MS).when(manager).getCurrentTimeInMillis();
        gson = new Gson();
    }

    @Test
    public void shouldCreateAManagerInstance() throws Exception {
        Context context = Robolectric.buildActivity(Activity.class).create().start().resume().get();
        AuthenticationAPIClient apiClient = new AuthenticationAPIClient(new Auth0("clientId", "domain"));
        Storage storage = new SharedPreferencesStorage(context);
        final SecureCredentialsManager manager = new SecureCredentialsManager(context, apiClient, storage);
        assertThat(manager, is(notNullValue()));
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
    public void shouldThrowOnSetIfCryptoError() throws Exception {
        exception.expect(CredentialsManagerException.class);
        exception.expectMessage("An error occurred while encrypting the credentials.");

        long expirationTime = CredentialsMock.CURRENT_TIME_MS + 123456 * 1000;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", new Date(expirationTime), "scope");
        when(crypto.encrypt(any(byte[].class))).thenThrow(new CryptoException("something", new Throwable("happened")));
        manager.saveCredentials(credentials);
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
        Date newDate = new Date(123412341234L);
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
        //Gson serializes to String dates and strips a few millis. Nothing critical..
        assertThat(renewedStoredCredentials.getExpiresAt().toString(), is(newDate.toString()));
        assertThat(renewedStoredCredentials.getScope(), is("newScope"));
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

    @Test
    public void shouldThrowOnInvalidAuthenticationRequestCode() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Request code must a value between 1 and 255.");
        Activity activity = Robolectric.buildActivity(Activity.class).create().start().resume().get();

        manager.requireAuthentication(activity, 256, null, null);
    }

    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    @Test
    @Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
    public void shouldNotRequireAuthenticationIfAPI21AndLockScreenDisabled() throws Exception {
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

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Test
    @Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 23, manifest = Config.NONE)
    public void shouldNotRequireAuthenticationIfAPI23AndLockScreenDisabled() throws Exception {
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

    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    @Test
    @Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
    public void shouldRequireAuthenticationIfAPI21AndLockScreenEnabled() throws Exception {
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

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Test
    @Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 23, manifest = Config.NONE)
    public void shouldRequireAuthenticationIfAPI23AndLockScreenEnabled() throws Exception {
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
    public void shouldGetCredentialsAfterAuthentication() throws Exception {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + 123456L * 1000);
        Credentials storedCredentials = new Credentials("idToken", "accessToken", "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);

        //Require authentication
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(true);
        Intent confirmCredentialsIntent = mock(Intent.class);
        when(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription")).thenReturn(confirmCredentialsIntent);
        boolean willRequireAuthentication = manager.requireAuthentication(activity, 123, "theTitle","theDescription");
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
        assertThat(retrievedCredentials.getRefreshToken(), is("refreshToken"));
        assertThat(retrievedCredentials.getType(), is("type"));
        assertThat(retrievedCredentials.getExpiresAt(), is(notNullValue()));
        assertThat(retrievedCredentials.getExpiresAt().getTime(), is(expiresAt.getTime()));
        assertThat(retrievedCredentials.getScope(), is("scope"));
    }

    @Test
    public void shouldNotGetCredentialsAfterCanceledAuthentication() throws Exception {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + 123456L * 1000);
        Credentials storedCredentials = new Credentials("idToken", "accessToken", "type", "refreshToken", expiresAt, "scope");
        String storedJson = gson.toJson(storedCredentials);
        String encoded = new String(Base64.encode(storedJson.getBytes(), Base64.DEFAULT));
        when(crypto.decrypt(storedJson.getBytes())).thenReturn(storedJson.getBytes());
        when(storage.retrieveString("com.auth0.credentials")).thenReturn(encoded);
        when(storage.retrieveLong("com.auth0.credentials_expires_at")).thenReturn(expiresAt.getTime());
        when(storage.retrieveBoolean("com.auth0.credentials_can_refresh")).thenReturn(false);

        //Require authentication
        Activity activity = spy(Robolectric.buildActivity(Activity.class).create().start().resume().get());
        KeyguardManager kService = mock(KeyguardManager.class);
        when(activity.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        when(kService.isKeyguardSecure()).thenReturn(true);
        Intent confirmCredentialsIntent = mock(Intent.class);
        when(kService.createConfirmDeviceCredentialIntent("theTitle", "theDescription")).thenReturn(confirmCredentialsIntent);
        boolean willRequireAuthentication = manager.requireAuthentication(activity, 123, "theTitle","theDescription");
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
}