package com.auth0.android.provider;

import android.app.Activity;
import android.app.Dialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.Resources;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.test.espresso.intent.matcher.IntentMatchers;
import android.util.Base64;
import android.webkit.URLUtil;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.hamcrest.core.Is;
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
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static android.support.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasFlag;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasHost;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasParamWithName;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasParamWithValue;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasPath;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasScheme;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
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
@Config(sdk = 18)
public class WebAuthProviderTest {

    private static final int REQUEST_CODE = 11;
    private static final String KEY_STATE = "state";
    private static final String KEY_NONCE = "nonce";
    private static final long FIXED_CLOCK_CURRENT_TIME_MS = 1567314000000L;

    @Mock
    private AuthCallback callback;
    @Mock
    private VoidCallback voidCallback;
    private Activity activity;
    private Auth0 account;

    @Captor
    private ArgumentCaptor<Auth0Exception> auth0ExceptionCaptor;
    @Captor
    private ArgumentCaptor<AuthenticationException> authExceptionCaptor;
    @Captor
    private ArgumentCaptor<Intent> intentCaptor;
    @Captor
    private ArgumentCaptor<AuthCallback> callbackCaptor;
    @Captor
    private ArgumentCaptor<VoidCallback> voidCallbackCaptor;


    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        activity = spy(Robolectric.buildActivity(Activity.class).get());
        account = new Auth0("my-client-id", "my-domain.com");

        //Next line is needed to avoid CustomTabService from being bound to Test environment
        //noinspection WrongConstant
        doReturn(false).when(activity).bindService(any(Intent.class), any(ServiceConnection.class), anyInt());

        //Next line is needed to tell a Browser app is installed
        prepareBrowserApp(true, null);
    }

    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//
    //** LOG IN  FEATURE **//
    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//

    @SuppressWarnings("deprecation")
    @Test
    public void shouldLoginWithAccount() {
        WebAuthProvider.login(account)
                .start(activity, callback, REQUEST_CODE);

        assertNotNull(WebAuthProvider.getManagerInstance());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldInitWithAccount() {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertNotNull(WebAuthProvider.getManagerInstance());
    }

    @Test
    public void shouldInitWithContext() {
        Context context = Mockito.mock(Context.class);
        Resources resources = Mockito.mock(Resources.class);
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), anyString())).thenReturn(222);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), anyString())).thenReturn(333);

        when(context.getString(eq(222))).thenReturn("clientId");
        when(context.getString(eq(333))).thenReturn("domain");

        WebAuthProvider.init(context)
                .start(activity, callback);

        assertNotNull(WebAuthProvider.getManagerInstance());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldNotResumeLoginWithRequestCodeWhenNotInit() {
        Intent intentMock = Mockito.mock(Intent.class);

        assertFalse(WebAuthProvider.resume(0, 0, intentMock));
    }

    @Test
    public void shouldNotResumeLoginWithIntentWhenNotInit() {
        Intent intentMock = Mockito.mock(Intent.class);

        assertFalse(WebAuthProvider.resume(intentMock));
    }

    //scheme

    @Test
    public void shouldHaveDefaultSchemeOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);
        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("redirect_uri"));
        Uri redirectUri = Uri.parse(uri.getQueryParameter("redirect_uri"));
        assertThat(redirectUri, hasScheme("https"));
    }

    @Test
    public void shouldSetSchemeOnLogin() {
        WebAuthProvider.init(account)
                .withScheme("myapp")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("redirect_uri"));
        Uri redirectUri = Uri.parse(uri.getQueryParameter("redirect_uri"));
        assertThat(redirectUri, hasScheme("myapp"));
    }

    //connection

    @Test
    public void shouldNotHaveDefaultConnectionOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("connection")));
    }

    @Test
    public void shouldSetConnectionFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection", (Object) "my-connection");
        WebAuthProvider.init(account)
                .withConnection("some-connection")
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection", "my-connection"));
    }

    @Test
    public void shouldSetConnectionFromSetterOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection", (Object) "my-connection");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withConnection("some-connection")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection", "some-connection"));
    }

    @Test
    public void shouldNotOverrideConnectionValueWithDefaultConnectionOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection", (Object) "my-connection");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection", "my-connection"));
    }

    @Test
    public void shouldSetConnectionOnLogin() {
        WebAuthProvider.init(account)
                .withConnection("some-connection")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection", "some-connection"));
    }

    //audience

    @Test
    public void shouldNotHaveDefaultAudienceOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("audience")));
    }

    @Test
    public void shouldSetAudienceFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("audience", (Object) "https://mydomain.auth0.com/myapi");
        WebAuthProvider.init(account)
                .withAudience("https://google.com/apis")
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("audience", "https://mydomain.auth0.com/myapi"));
    }

    @Test
    public void shouldSetAudienceFromSetterOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("audience", (Object) "https://mydomain.auth0.com/myapi");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withAudience("https://google.com/apis")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("audience", "https://google.com/apis"));
    }

    @Test
    public void shouldNotOverrideAudienceValueWithDefaultAudienceOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("audience", (Object) "https://mydomain.auth0.com/myapi");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("audience", "https://mydomain.auth0.com/myapi"));
    }

    @Test
    public void shouldSetAudienceOnLogin() {
        WebAuthProvider.init(account)
                .withAudience("https://google.com/apis")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("audience", "https://google.com/apis"));
    }


    //scope

    @Test
    public void shouldHaveDefaultScopeOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "openid"));
    }

    @Test
    public void shouldSetScopeFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("scope", (Object) "openid email contacts");
        WebAuthProvider.init(account)
                .withScope("profile super_scope")
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "openid email contacts"));
    }

    @Test
    public void shouldSetScopeFromSetterOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("scope", (Object) "openid email contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withScope("profile super_scope")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "profile super_scope"));
    }

    @Test
    public void shouldNotOverrideScopeValueWithDefaultScopeOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("scope", (Object) "openid email contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "openid email contacts"));
    }

    @Test
    public void shouldSetScopeOnLogin() {
        WebAuthProvider.init(account)
                .withScope("profile super_scope")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "profile super_scope"));
    }


    //connection scope

    @Test
    public void shouldNotHaveDefaultConnectionScopeOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("connection_scope")));
    }

    @Test
    public void shouldSetConnectionScopeFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection_scope", (Object) "openid,email,contacts");
        WebAuthProvider.init(account)
                .withConnectionScope("profile", "super_scope")
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection_scope", "openid,email,contacts"));
    }

    @Test
    public void shouldSetConnectionScopeFromSetterOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection_scope", (Object) "openid,email,contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withConnectionScope("profile", "super_scope")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection_scope", "profile,super_scope"));
    }

    @Test
    public void shouldNotOverrideConnectionScopeValueWithDefaultConnectionScopeOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection_scope", (Object) "openid,email,contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection_scope", "openid,email,contacts"));
    }

    @Test
    public void shouldSetConnectionScopeOnLogin() {
        WebAuthProvider.init(account)
                .withConnectionScope("the", "scope", "of", "my", "connection")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection_scope", "the,scope,of,my,connection"));
    }


    //state

    @Test
    public void shouldHaveDefaultStateOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("state"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetNonNullStateOnLogin() {
        WebAuthProvider.init(account)
                .withState(null)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("state"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetStateFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("state", (Object) "1234567890");
        WebAuthProvider.init(account)
                .withState("abcdefg")
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("state", "1234567890"));
    }

    @Test
    public void shouldSetStateFromSetterOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("state", (Object) "1234567890");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withState("abcdefg")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("state", "abcdefg"));
    }

    @Test
    public void shouldNotOverrideStateValueWithDefaultStateOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("state", (Object) "1234567890");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("state", "1234567890"));
    }

    @Test
    public void shouldSetStateOnLogin() {
        WebAuthProvider.init(account)
                .withState("abcdefg")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("state", "abcdefg"));
    }

    //nonce

    @Test
    public void shouldSetNonceByDefaultIfResponseTypeIncludesCodeOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("nonce"));
    }

    @Test
    public void shouldSetNonceByDefaultIfResponseTypeIncludesIdTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("nonce"));
    }

    @Test
    public void shouldNotSetNonceByDefaultIfResponseTypeIsTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("nonce")));
    }

    @Test
    public void shouldSetNonNullNonceOnLogin() {
        WebAuthProvider.init(account)
                .withNonce(null)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("nonce"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetUserNonceIfResponseTypeIsTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .withNonce("1234567890")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetUserNonceIfResponseTypeIsCodeOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .withNonce("1234567890")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetNonceFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("nonce", (Object) "1234567890");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withNonce("abcdefg")
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetNonceFromSetterOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("nonce", (Object) "1234567890");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withParameters(parameters)
                .withNonce("abcdefg")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("nonce", "abcdefg"));
    }

    @Test
    public void shouldNotOverrideNonceValueWithDefaultNonceOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("nonce", (Object) "1234567890");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetNonceOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withNonce("abcdefg")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("nonce", "abcdefg"));
    }

    @Test
    public void shouldGenerateRandomStringIfDefaultValueIsMissingOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);
        String random1 = OAuthManager.getRandomString(null);
        String random2 = OAuthManager.getRandomString(null);

        assertThat(random1, is(notNullValue()));
        assertThat(random2, is(notNullValue()));
        assertThat(random1, is(not(equalTo(random2))));
    }

    @Test
    public void shouldNotGenerateRandomStringIfDefaultValuePresentOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);
        String random1 = OAuthManager.getRandomString("some");
        String random2 = OAuthManager.getRandomString("some");

        assertThat(random1, is("some"));
        assertThat(random2, is("some"));
    }


    // auth0 related

    @Test
    public void shouldHaveClientIdOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("client_id", "my-client-id"));
    }

    @Test
    public void shouldHaveTelemetryInfoOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("auth0Client"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldHaveRedirectUriOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri.getQueryParameter("redirect_uri"), is("https://my-domain.com/android/com.auth0.android.auth0.test/callback"));
    }

    //response type

    @Test
    public void shouldHaveDefaultResponseTypeOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "token"));
    }

    @Test
    public void shouldSetResponseTypeIdTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "id_token"));
    }

    @Test
    public void shouldSetResponseTypeCodeOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeCodeTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code id_token"));
    }

    @Test
    public void shouldSetResponseTypeIdTokenTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "id_token token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdTokenTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code id_token token"));
    }

    @Test
    public void shouldSetNonNullAuthenticationParametersOnLogin() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("a", "valid");
        parameters.put("b", null);
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("a", "valid"));
        assertThat(uri, not(hasParamWithName("b")));
    }

    @Test
    public void shouldBuildAuthorizeURIWithoutNullsOnLogin() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        Set<String> params = uri.getQueryParameterNames();
        for (String name : params) {
            assertThat(uri, not(hasParamWithValue(name, null)));
            assertThat(uri, not(hasParamWithValue(name, "null")));
        }
    }

    @Test
    public void shouldBuildAuthorizeURIWithCorrectSchemeHostAndPathOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withState("a-state")
                .withNonce("a-nonce")
                .start(activity, callback);

        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());
        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasScheme(baseUriString.getScheme()));
        assertThat(uri, hasHost(baseUriString.getHost()));
        assertThat(uri, hasPath(baseUriString.getPath()));
    }

    @Test
    public void shouldBuildAuthorizeURIWithResponseTypeIdTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withState("a-state")
                .withNonce("a-nonce")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("nonce", "a-nonce"));
        assertThat(uri, not(hasParamWithName("code_challenge")));
        assertThat(uri, not(hasParamWithName("code_challenge_method")));
        assertThat(uri, hasParamWithValue("response_type", "id_token"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithResponseTypeTokenOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .withState("a-state")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("nonce")));
        assertThat(uri, not(hasParamWithName("code_challenge")));
        assertThat(uri, not(hasParamWithName("code_challenge_method")));
        assertThat(uri, hasParamWithValue("response_type", "token"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithResponseTypeCodeOnLogin() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .withState("a-state")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("nonce"));
        assertThat(uri, hasParamWithValue(is("code_challenge"), not(isEmptyOrNullString())));
        assertThat(uri, hasParamWithValue("code_challenge_method", "S256"));
        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldStartLoginWithBrowserCustomTabsOptions() {
        CustomTabsOptions options = mock(CustomTabsOptions.class);
        WebAuthProvider.init(account)
                .withCustomTabsOptions(options)
                .useCodeGrant(false)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent.getData(), is(nullValue()));

        Bundle extras = intentCaptor.getValue().getExtras();
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(notNullValue()));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat((CustomTabsOptions) extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(options));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldStartLoginWithBrowser() {
        WebAuthProvider.init(account)
                .useBrowser(true)
                .useCodeGrant(false)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent.getData(), is(nullValue()));

        Bundle extras = intentCaptor.getValue().getExtras();
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(notNullValue()));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(nullValue()));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldStartLoginWithWebViewAndDefaultConnection() {
        WebAuthProvider.init(account)
                .useBrowser(false)
                .useCodeGrant(false)
                .useFullscreen(false)
                .start(activity, callback, REQUEST_CODE);

        verify(activity).startActivityForResult(intentCaptor.capture(), any(Integer.class));

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent.getData(), is(nullValue()));

        Bundle extras = intentCaptor.getValue().getExtras();
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(notNullValue()));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(true));
        assertThat(extras.getString(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(nullValue()));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS), is(false));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldStartLoginWithWebViewAndCustomConnection() {
        WebAuthProvider.init(account)
                .useBrowser(false)
                .withConnection("my-connection")
                .useCodeGrant(false)
                .useFullscreen(true)
                .start(activity, callback);

        verify(activity).startActivityForResult(intentCaptor.capture(), any(Integer.class));

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent.getData(), is(nullValue()));

        Bundle extras = intent.getExtras();
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(notNullValue()));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(true));
        assertThat(extras.getString(AuthenticationActivity.EXTRA_CONNECTION_NAME), is("my-connection"));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(true));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS), is(false));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldSetExpectedNonceWithResponseTypeIdToken() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback, REQUEST_CODE);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        String sentNonce = uri.getQueryParameter(KEY_NONCE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));

        String expectedIdToken = customNonceJWT(sentNonce);
        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, sentState, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeLoginWithIntentWithResponseTypeIdToken() {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        String sentNonce = uri.getQueryParameter(KEY_NONCE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));

        String expectedIdToken = customNonceJWT(sentNonce);
        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, sentState, null, null));
        assertTrue(WebAuthProvider.resume(intent));


        verify(callback).onSuccess(any(Credentials.class));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldStartLoginWithValidRequestCode() {
        final Credentials credentials = Mockito.mock(Credentials.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callback.onSuccess(credentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), eq(callback));

        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, "1234567890", null, null));
        int DEFAULT_REQUEST_CODE = 110;
        assertTrue(WebAuthProvider.resume(DEFAULT_REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeLoginWithIntentWithCodeGrant() {
        Date expiresAt = new Date();
        PKCE pkce = Mockito.mock(PKCE.class);
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        String sentNonce = uri.getQueryParameter(KEY_NONCE);

        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, sentState, null, null));

        String expectedIdToken = customNonceJWT(sentNonce);
        final Credentials codeCredentials = new Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());

        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(expectedIdToken));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("codeAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("codeRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("codeType"));
        assertThat(credentialsCaptor.getValue().getExpiresAt(), is(expiresAt));
        assertThat(credentialsCaptor.getValue().getScope(), is("codeScope"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeLoginWithRequestCodeWithCodeGrant() {
        Date expiresAt = new Date();
        PKCE pkce = Mockito.mock(PKCE.class);

        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback, REQUEST_CODE);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        String sentNonce = uri.getQueryParameter(KEY_NONCE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, sentState, null, null));

        String expectedIdToken = customNonceJWT(sentNonce);
        final Credentials codeCredentials = new Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());


        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(expectedIdToken));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("codeAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("codeRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("codeType"));
        assertThat(credentialsCaptor.getValue().getExpiresAt(), is(expiresAt));
        assertThat(credentialsCaptor.getValue().getScope(), is("codeScope"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeLoginWithIntentWithImplicitGrant() {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, "urlAccess", null, "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("urlAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getType(), is("urlType"));
        assertThat(credentialsCaptor.getValue().getExpiresIn(), is(1111L));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeLoginWithRequestCodeWithImplicitGrant() {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, "urlAccess", null, "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("urlAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getType(), is("urlType"));
        assertThat(credentialsCaptor.getValue().getExpiresIn(), is(1111L));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeLoginWithRequestCodeWhenResultCancelled() {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        Intent intent = createAuthIntent(null);
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_CANCELED, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.authentication_canceled"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The user closed the browser app and the authentication was canceled."));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeLoginWithIntentWhenResultCancelled() {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        Intent intent = createAuthIntent(null);
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.authentication_canceled"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The user closed the browser app and the authentication was canceled."));
    }

    @Test
    public void shouldCalculateExpiresAtDateOnResumeLogin() {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, "urlAccess", null, "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        long expirationTime = FIXED_CLOCK_CURRENT_TIME_MS + 1111L * 1000;
        assertThat(credentialsCaptor.getValue().getExpiresAt(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getExpiresAt().getTime(), is(expirationTime));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldReThrowAnyFailedCodeExchangeDialogOnLogin() {
        final Dialog dialog = Mockito.mock(Dialog.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onFailure(dialog);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, null, null, null, 1111L, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(dialog);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldReThrowAnyFailedCodeExchangeExceptionOnLogin() {
        final AuthenticationException exception = Mockito.mock(AuthenticationException.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onFailure(exception);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, null, null, null, 1111L, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(exception);
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithIntentWithAccessDenied() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "access_denied", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithAccessDenied() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "access_denied", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithIntentWithRuleError() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "unauthorized", "Custom Rule Error"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("unauthorized"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Custom Rule Error"));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithRuleError() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "unauthorized", "Custom Rule Error"));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("unauthorized"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Custom Rule Error"));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithIntentWithConfigurationInvalid() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "some other error", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithConfigurationInvalid() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "some other error", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithIntentWithLoginRequired() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "login_required", "Login Required"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("login_required"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Login Required"));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithLoginRequired() {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "login_required", "Login Required"));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("login_required"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Login Required"));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithIntentWithInvalidState() {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithInvalidState() {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithIntentWithInvalidNonce() {
        WebAuthProvider.init(account)
                .withState("state")
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        String expectedIdToken = customNonceJWT("abcdefg");
        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "state", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.sdk.internal_error.id_token_validation"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Nonce (nonce) claim mismatch in the ID token; expected \"0987654321\", found \"abcdefg\""));
    }

    @SuppressWarnings({"deprecation"})
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithInvalidNonce() {
        WebAuthProvider.init(account)
                .withState("state")
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback, REQUEST_CODE);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        String expectedIdToken = customNonceJWT("abcdefg");
        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "state", null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.sdk.internal_error.id_token_validation"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Nonce (nonce) claim mismatch in the ID token; expected \"0987654321\", found \"abcdefg\""));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeLoginWithUnexpectedRequestCode() {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        Intent intent = createAuthIntent(createHash(null, "aToken", null, null, null, "1234567890", null, null));
        assertFalse(WebAuthProvider.resume(999, Activity.RESULT_OK, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeLoginWithResultNotOK() {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        Intent intent = createAuthIntent(createHash(null, "aToken", null, null, null, "1234567890", null, null));
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, 999, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeLoginWithIntentWithEmptyUriValues() {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback);

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithEmptyUriValues() {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithoutFirstInitProvider() {
        WebAuthProvider.resetManagerInstance();

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithoutFirstInitProvider() {
        WebAuthProvider.resetManagerInstance();

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeLoginWithIntentWithNullIntent() {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback);
        assertFalse(WebAuthProvider.resume(null));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithNullIntent() {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, null));
    }

    @Test
    public void shouldClearInstanceAfterSuccessLoginWithIntent() {
        WebAuthProvider.init(account)
                .start(activity, callback);

        assertThat(WebAuthProvider.getManagerInstance(), is(notNullValue()));
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldClearInstanceAfterSuccessLoginWithRequestCode() {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertThat(WebAuthProvider.getManagerInstance(), is(notNullValue()));
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @Test
    public void shouldFailToStartLoginWithBrowserWhenNoBrowserAppIsInstalled() {
        prepareBrowserApp(false, null);
        WebAuthProvider.init(account)
                .useBrowser(true)
                .start(activity, callback);

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.browser_not_available"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("No Browser application installed to perform web authentication."));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldNotFailToStartLoginWithWebviewWhenNoBrowserAppIsInstalled() {
        prepareBrowserApp(false, null);
        WebAuthProvider.init(account)
                .useBrowser(false)
                .start(activity, callback, REQUEST_CODE);

        verify(activity).startActivityForResult(intentCaptor.capture(), any(Integer.class));

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent.getData(), is(nullValue()));

        verify(callback, never()).onFailure(any(AuthenticationException.class));
    }

    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//
    //** LOG OUT FEATURE **//
    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//

    @Test
    public void shouldInitLogoutWithAccount() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        assertNotNull(WebAuthProvider.getManagerInstance());
    }

    //scheme

    @Test
    public void shouldHaveDefaultSchemeOnLogout() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);
        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("returnTo"));
        Uri returnToUri = Uri.parse(uri.getQueryParameter("returnTo"));
        assertThat(returnToUri, hasScheme("https"));
    }

    @Test
    public void shouldSetSchemeOnLogout() {
        WebAuthProvider.logout(account)
                .withScheme("myapp")
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("returnTo"));
        Uri returnToUri = Uri.parse(uri.getQueryParameter("returnTo"));
        assertThat(returnToUri, hasScheme("myapp"));
    }

    // client id

    @Test
    public void shouldAlwaysSetClientIdOnLogout() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("client_id", "my-client-id"));
    }

    // auth0 related

    @Test
    public void shouldHaveTelemetryInfoOnLogout() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("auth0Client"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldHaveReturnToUriOnLogout() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri.getQueryParameter("returnTo"), is("https://my-domain.com/android/com.auth0.android.auth0.test/callback"));
    }


    // Launch log out


    @Test
    public void shouldStartLogout() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent.getData(), is(nullValue()));

        Bundle extras = intentCaptor.getValue().getExtras();
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(notNullValue()));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(nullValue()));
    }

    @Test
    public void shouldStartLogoutWithCustomTabsOptions() {
        CustomTabsOptions options = mock(CustomTabsOptions.class);
        WebAuthProvider.logout(account)
                .withCustomTabsOptions(options)
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent.getData(), is(nullValue()));

        Bundle extras = intentCaptor.getValue().getExtras();
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(notNullValue()));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CT_OPTIONS), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat((CustomTabsOptions) extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(options));
    }

    @Test
    public void shouldFailToStartLogoutWhenNoBrowserAppIsInstalled() {
        prepareBrowserApp(false, null);
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        verify(voidCallback).onFailure(auth0ExceptionCaptor.capture());

        assertThat(auth0ExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(auth0ExceptionCaptor.getValue().getMessage(), is("Cannot perform web log out"));
        Throwable cause = auth0ExceptionCaptor.getValue().getCause();
        assertThat(cause, is(CoreMatchers.<Throwable>instanceOf(ActivityNotFoundException.class)));
        assertThat(cause.getMessage(), is("No Browser application installed."));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @Test
    public void shouldResumeLogoutSuccessfullyWithIntent() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        Intent intent = createAuthIntent("");
        assertTrue(WebAuthProvider.resume(intent));

        verify(voidCallback).onSuccess(any(Void.class));
    }

    @Test
    public void shouldResumeLogoutFailingWithIntent() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        //null data translates to result canceled
        Intent intent = createAuthIntent(null);
        assertTrue(WebAuthProvider.resume(intent));

        verify(voidCallback).onFailure(auth0ExceptionCaptor.capture());

        assertThat(auth0ExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(auth0ExceptionCaptor.getValue().getMessage(), is("The user closed the browser app so the logout was cancelled."));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @Test
    public void shouldClearLogoutManagerInstanceAfterSuccessfulLogout() {
        WebAuthProvider.logout(account)
                .start(activity, voidCallback);

        assertThat(WebAuthProvider.getManagerInstance(), is(notNullValue()));
        Intent intent = createAuthIntent("");
        assertTrue(WebAuthProvider.resume(intent));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }


    //**  ** ** ** ** **  **//
    //**  ** ** ** ** **  **//
    //**Tests for Utilities**//
    //**  ** ** ** ** **  **//
    //**  ** ** ** ** **  **//

    @Test
    public void shouldHaveBrowserAppInstalled() {
        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        prepareBrowserApp(true, intentCaptor);

        boolean hasBrowserApp = WebAuthProvider.hasBrowserAppInstalled(activity.getPackageManager());
        MatcherAssert.assertThat(hasBrowserApp, Is.is(true));
        MatcherAssert.assertThat(intentCaptor.getValue(), Is.is(IntentMatchers.hasAction(Intent.ACTION_VIEW)));
        MatcherAssert.assertThat(URLUtil.isValidUrl(intentCaptor.getValue().getDataString()), Is.is(true));
    }

    @Test
    public void shouldNotHaveBrowserAppInstalled() {
        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        prepareBrowserApp(false, intentCaptor);

        boolean hasBrowserApp = WebAuthProvider.hasBrowserAppInstalled(activity.getPackageManager());
        MatcherAssert.assertThat(hasBrowserApp, Is.is(false));
        MatcherAssert.assertThat(intentCaptor.getValue(), Is.is(IntentMatchers.hasAction(Intent.ACTION_VIEW)));
        MatcherAssert.assertThat(URLUtil.isValidUrl(intentCaptor.getValue().getDataString()), Is.is(true));
    }

    //**  ** ** ** ** **  **//
    //**  ** ** ** ** **  **//
    //** Helpers Functions**//
    //**  ** ** ** ** **  **//
    //**  ** ** ** ** **  **//

    private Intent createAuthIntent(@Nullable String hash) {
        Intent intent = new Intent();
        if (hash == null) {
            return intent;
        }
        Uri validUri = Uri.parse("https://domain.auth0.com/android/package/callback" + hash);
        intent.setData(validUri);
        return intent;
    }

    private void prepareBrowserApp(boolean isAppInstalled, @Nullable ArgumentCaptor<Intent> intentCaptor) {
        PackageManager pm = mock(PackageManager.class);
        ResolveInfo info = null;
        if (isAppInstalled) {
            info = mock(ResolveInfo.class);
            ApplicationInfo appInfo = mock(ApplicationInfo.class);
            appInfo.packageName = "com.auth0.test";
            ActivityInfo actInfo = mock(ActivityInfo.class);
            actInfo.applicationInfo = appInfo;
            actInfo.name = "Auth0 Browser";
            info.activityInfo = actInfo;
        }
        when(pm.resolveActivity(intentCaptor != null ? intentCaptor.capture() : any(Intent.class), eq(PackageManager.MATCH_DEFAULT_ONLY))).thenReturn(info);
        when(activity.getPackageManager()).thenReturn(pm);
    }

    private String createHash(@Nullable String idToken, @Nullable String accessToken, @Nullable String refreshToken, @Nullable String tokenType, @Nullable Long expiresIn, @Nullable String state, @Nullable String error, @Nullable String errorDescription) {
        String hash = "#";
        if (accessToken != null) {
            hash = hash.concat("access_token=")
                    .concat(accessToken)
                    .concat("&");
        }
        if (idToken != null) {
            hash = hash.concat("id_token=")
                    .concat(idToken)
                    .concat("&");
        }
        if (refreshToken != null) {
            hash = hash.concat("refresh_token=")
                    .concat(refreshToken)
                    .concat("&");
        }
        if (tokenType != null) {
            hash = hash.concat("token_type=")
                    .concat(tokenType)
                    .concat("&");
        }
        if (expiresIn != null) {
            hash = hash.concat("expires_in=")
                    .concat(String.valueOf(expiresIn))
                    .concat("&");
        }
        if (state != null) {
            hash = hash.concat("state=")
                    .concat(state)
                    .concat("&");
        }
        if (error != null) {
            hash = hash.concat("error=")
                    .concat(error)
                    .concat("&");
        }
        if (errorDescription != null) {
            hash = hash.concat("error_description=")
                    .concat(errorDescription)
                    .concat("&");
        }
        if (hash.endsWith("&")) {
            hash = hash.substring(0, hash.length() - 1);
        }
        return hash.length() == 1 ? "" : hash;
    }

    private String customNonceJWT(@NonNull String nonce) {
        long iat = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
        long exp = iat + 3600;
        String header = "{" +
                "\"alg\":\"HS256\"," +
                "\"typ\":\"JWT\"" +
                "}";
        String body = "{" +
                "\"iss\":\"https://my-domain.com/\"," +
                "\"sub\":\"auth0|123456789\"," +
                "\"aud\": [" +
                "\"my-client-id\"," +
                "\"other-client-id\"" +
                "]," +
                "\"exp\":" + exp + "," +
                "\"iat\":" + iat + "," +
                "\"auth_time\":" + iat + "," +
                "\"azp\":\"my-client-id\"," +
                "\"nonce\":\"" + nonce + "\"" +
                "}";
        String signature = "sign";

        String encodedHeader = encodeString(header);
        String encodedBody = encodeString(body);
        return String.format("%s.%s.%s", encodedHeader, encodedBody, signature);
    }

    private String encodeString(String source) {
        byte[] bytes = Base64.encode(source.getBytes(), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        String res = "";
        try {
            res = new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException ignored) {
        }
        return res;
    }
}