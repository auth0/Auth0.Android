package com.auth0.android.provider;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.Nullable;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(RobolectricGradleTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 18, manifest = Config.NONE)
public class WebAuthProviderTest {

    private static final String CALLBACK_URL = "https://my-domain.auth0.com/android/com.auth0.android.lock.app/callback";

    private static final int REQUEST_CODE = 11;
    private static final String CONNECTION_NAME = "connection";
    private static final String SCOPE = "scope";
    private static final String STATE = "state";
    private static final String USERNAME_PASSWORD_AUTHENTICATION_CONNECTION = "Username-Password-Authentication";
    private static final String SCOPE_OPEN_ID = "openid";

    @Mock
    private AuthCallback callback;
    private Activity activity;
    private Auth0 account;

    @Captor
    private ArgumentCaptor<AuthenticationException> authExceptionCaptor;


    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        activity = Robolectric.buildActivity(Activity.class).get();
        account = new Auth0("clientId", "domain");
    }

    @Test
    public void shouldInit() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertNotNull(WebAuthProvider.getInstance());
    }

    @Test
    public void shouldHaveDefaultsOnInit() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.useBrowser(), is(true));
        assertThat(instance.useCodeGrant(), is(true));
        assertThat(instance.useFullscreen(), is(false));
        assertThat(instance.getConnection(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getScope(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getState(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getParameters(), is(notNullValue()));
        assertThat(instance.getParameters().isEmpty(), is(true));
    }

    @Test
    public void shouldHaveDefaultConnection() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getConnection(), is(USERNAME_PASSWORD_AUTHENTICATION_CONNECTION));
    }

    @Test
    public void shouldHaveDefaultScope() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getScope(), is(SCOPE_OPEN_ID));
    }

    @Test
    public void shouldConfigureAfterInit() throws Exception {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("key", "value");

        WebAuthProvider.init(account)
                .useBrowser(true)
                .useCodeGrant(true)
                .useFullscreen(true)
                .withConnection(CONNECTION_NAME)
                .withScope(SCOPE)
                .withState(STATE)
                .withParameters(parameters)
                .start(activity, callback, REQUEST_CODE);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.useBrowser(), is(true));
        assertThat(instance.useCodeGrant(), is(true));
        assertThat(instance.useFullscreen(), is(true));
        assertThat(instance.getConnection(), is(CONNECTION_NAME));
        assertThat(instance.getScope(), is(SCOPE));
        assertThat(instance.getState(), is(STATE));
        assertThat(instance.getParameters(), is(notNullValue()));
        assertThat(instance.getParameters(), Matchers.hasEntry("key", (Object) "value"));
    }

    @Test
    public void shouldBeInvalidWhenResumedButNeverInited() throws Exception {
        Intent intentMock = Mockito.mock(Intent.class);

        assertFalse(WebAuthProvider.resume(intentMock));
        assertFalse(WebAuthProvider.resume(0, 0, intentMock));
    }

    @Test
    public void shouldFailToStartWithInvalidAuthorizeURI() throws Exception {
        Auth0 account = Mockito.mock(Auth0.class);
        when(account.getAuthorizeUrl()).thenReturn(null);

        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_authorize_url"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Auth0 authorize URL not properly set. This can be related to an invalid domain."));
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @Test
    public void shouldResumeWithIntentWithCodeGrant() throws Exception {
        final Credentials credentials = Mockito.mock(Credentials.class);
        final PKCE pkce = Mockito.spy(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callback.onSuccess(credentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), eq(callback));

        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldClearInstanceAfterSuccessAuthentication() throws Exception {
        final Credentials credentials = Mockito.mock(Credentials.class);
        final PKCE pkce = Mockito.spy(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callback.onSuccess(credentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), eq(callback));
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeWithRequestCodeWithCodeGrant() throws Exception {
        final Credentials credentials = Mockito.mock(Credentials.class);
        final PKCE pkce = Mockito.spy(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callback.onSuccess(credentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), eq(callback));

        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeWithIntentWithImplicitGrant() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeWithRequestCodeWithImplicitGrant() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldFailToResumeWithIntentWithAccessDenied() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", "access_denied"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @Test
    public void shouldFailToResumeWithRequestCodeWithAccessDenied() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", "access_denied"));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @Test
    public void shouldFailToResumeWithIntentWithConfigurationInvalid() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", "some other error"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @Test
    public void shouldFailToResumeWithRequestCodeWithConfigurationInvalid() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", "some other error"));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @Test
    public void shouldFailToResumeWithIntentWithInvalidState() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @Test
    public void shouldFailToResumeWithRequestCodeWithInvalidState() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @Test
    public void shouldFailToResumeWithUnexpectedRequestCode() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertFalse(WebAuthProvider.resume(999, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldFailToResumeWithResultCancelled() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_CANCELED, intent));
    }

    @Test
    public void shouldFailToResumeWithResultNotOK() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, 999, intent));
    }

    @Test
    public void shouldFailToResumeWithIntentWithEmptyUriValues() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        final Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @Test
    public void shouldHavePKCEEnabled() throws Exception{
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .start(activity, callback, REQUEST_CODE);

        assertTrue(WebAuthProvider.getInstance().shouldUsePKCE());
    }


    @Test
    public void shouldHavePKCEDisabled() throws Exception{
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        assertFalse(WebAuthProvider.getInstance().shouldUsePKCE());
    }

    public void shouldFailToResumeWithRequestCodeWithEmptyUriValues() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        final Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldFailToResumeWithIntentWithoutFirstInitProvider() throws Exception {
        final Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @Test
    public void shouldFailToResumeWithRequestCodeWithoutFirstInitProvider() throws Exception {
        final Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldFailToResumeWithIntentWithNullIntent() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        assertFalse(WebAuthProvider.resume(null));
    }

    @Test
    public void shouldFailToResumeWithRequestCodeWithNullIntent() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, null));
    }

    @Test
    public void shouldClearInstanceAfterSuccessAuthenticationWithIntent() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertThat(WebAuthProvider.getInstance(), is(notNullValue()));
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        WebAuthProvider.resume(intent);
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @Test
    public void shouldClearInstanceAfterSuccessAuthenticationWithRequestCode() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertThat(WebAuthProvider.getInstance(), is(notNullValue()));
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent);
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    private Intent createAuthIntent(String hash) {
        Uri validUri = Uri.parse(CALLBACK_URL + hash);
        Intent intent = new Intent();
        intent.setData(validUri);
        return intent;
    }

    private String createHash(@Nullable String accessToken, @Nullable String idToken, @Nullable String tokenType, @Nullable String state, @Nullable String error) {
        String hash = "#";
        if (accessToken != null) {
            hash = hash.concat("access_token=" + accessToken);
        }
        if (idToken != null) {
            if (!hash.endsWith("&")) {
                hash = hash.concat("&");
            }
            hash = hash.concat("id_token=" + idToken);
        }
        if (tokenType != null) {
            if (!hash.endsWith("&")) {
                hash = hash.concat("&");
            }
            hash = hash.concat("token_type=" + tokenType);
        }
        if (state != null) {
            if (!hash.endsWith("&")) {
                hash = hash.concat("&");
            }
            hash = hash.concat("state=" + state);
        }
        if (error != null) {
            if (!hash.endsWith("&")) {
                hash = hash.concat("&");
            }
            hash = hash.concat("error=" + error);
        }
        return hash.length() == 1 ? "" : hash;
    }
}