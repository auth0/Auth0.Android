package com.auth0.android.provider;

import android.app.Activity;
import android.app.Dialog;
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
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;

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
    private static final long CURRENT_TIME_MS = 1234567890000L;

    @Mock
    private AuthCallback callback;
    private Activity activity;
    private Auth0 account;

    @Captor
    private ArgumentCaptor<AuthenticationException> authExceptionCaptor;
    @Captor
    private ArgumentCaptor<Intent> intentCaptor;
    @Captor
    private ArgumentCaptor<AuthCallback> callbackCaptor;


    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        activity = spy(Robolectric.buildActivity(Activity.class).get());
        account = new Auth0("clientId", "domain");

        //Next line is needed to avoid CustomTabService from being bound to Test environment
        //noinspection WrongConstant
        doReturn(false).when(activity).bindService(any(Intent.class), any(ServiceConnection.class), anyInt());

        //Next line is needed to tell a Browser app is installed
        prepareBrowserApp(true, null);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldInitWithAccount() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertNotNull(WebAuthProvider.getInstance());
    }

    @Test
    public void shouldInitWithContext() throws Exception {
        Context context = Mockito.mock(Context.class);
        Resources resources = Mockito.mock(Resources.class);
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), anyString())).thenReturn(222);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), anyString())).thenReturn(333);

        when(context.getString(eq(222))).thenReturn("clientId");
        when(context.getString(eq(333))).thenReturn("domain");

        WebAuthProvider.init(context)
                .start(activity, callback);

        assertNotNull(WebAuthProvider.getInstance());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldNotResumeWhenNotInit() throws Exception {
        Intent intentMock = Mockito.mock(Intent.class);

        assertFalse(WebAuthProvider.resume(intentMock));
        assertFalse(WebAuthProvider.resume(0, 0, intentMock));
    }

    //scheme

    @Test
    public void shouldHaveDefaultScheme() throws Exception {
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
    public void shouldSetScheme() throws Exception {
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
    public void shouldNotHaveDefaultConnection() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("connection")));
    }

    @Test
    public void shouldSetConnectionFromParameters() throws Exception {
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
    public void shouldSetConnectionFromSetter() throws Exception {
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
    public void shouldNotOverrideConnectionValueWithDefaultConnection() throws Exception {
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
    public void shouldSetConnection() throws Exception {
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
    public void shouldNotHaveDefaultAudience() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("audience")));
    }

    @Test
    public void shouldSetAudienceFromParameters() throws Exception {
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
    public void shouldSetAudienceFromSetter() throws Exception {
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
    public void shouldNotOverrideAudienceValueWithDefaultAudience() throws Exception {
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
    public void shouldSetAudience() throws Exception {
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
    public void shouldHaveDefaultScope() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "openid"));
    }

    @Test
    public void shouldSetScopeFromParameters() throws Exception {
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
    public void shouldSetScopeFromSetter() throws Exception {
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
    public void shouldNotOverrideScopeValueWithDefaultScope() throws Exception {
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
    public void shouldSetScope() throws Exception {
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
    public void shouldNotHaveDefaultConnectionScope() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("connection_scope")));
    }

    @Test
    public void shouldSetConnectionScopeFromParameters() throws Exception {
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
    public void shouldSetConnectionScopeFromSetter() throws Exception {
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
    public void shouldNotOverrideConnectionScopeValueWithDefaultConnectionScope() throws Exception {
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
    public void shouldSetConnectionScope() throws Exception {
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
    public void shouldHaveDefaultState() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("state"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetNonNullState() throws Exception {
        WebAuthProvider.init(account)
                .withState(null)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("state"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetStateFromParameters() throws Exception {
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
    public void shouldSetStateFromSetter() throws Exception {
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
    public void shouldNotOverrideStateValueWithDefaultState() throws Exception {
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
    public void shouldSetState() throws Exception {
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
    public void shouldNotSetNonceByDefaultIfResponseTypeIsCode() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("nonce")));
    }

    @Test
    public void shouldNotSetNonceByDefaultIfResponseTypeIsToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("nonce")));
    }

    @Test
    public void shouldHaveDefaultNonce() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("nonce"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetNonNullNonce() throws Exception {
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
    public void shouldSetUserNonceIfResponseTypeIsToken() throws Exception {
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
    public void shouldSetUserNonceIfResponseTypeIsCode() throws Exception {
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
    public void shouldSetNonceFromParameters() throws Exception {
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
    public void shouldSetNonceFromSetter() throws Exception {
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
    public void shouldNotOverrideNonceValueWithDefaultNonce() throws Exception {
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
    public void shouldSetNonce() throws Exception {
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
    public void shouldGenerateRandomStringIfDefaultValueMissing() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);
        String random1 = OAuthManager.getRandomString(null);
        String random2 = OAuthManager.getRandomString(null);

        assertThat(random1, is(notNullValue()));
        assertThat(random2, is(notNullValue()));
        assertThat(random1, is(not(equalTo(random2))));
    }

    @Test
    public void shouldNotGenerateRandomStringIfDefaultValuePresent() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);
        String random1 = OAuthManager.getRandomString("some");
        String random2 = OAuthManager.getRandomString("some");

        assertThat(random1, is("some"));
        assertThat(random2, is("some"));
    }


    // auth0 related

    @Test
    public void shouldHaveClientId() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("client_id", "clientId"));
    }

    @Test
    public void shouldHaveTelemetryInfo() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("auth0Client"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldHaveRedirectUri() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri.getQueryParameter("redirect_uri"), is("https://domain/android/com.auth0.android.auth0.test/callback"));
    }

    //response type

    @Test
    public void shouldHaveDefaultResponseType() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "token"));
    }

    @Test
    public void shouldSetResponseTypeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "id_token"));
    }

    @Test
    public void shouldSetResponseTypeCode() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeCodeToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code id_token"));
    }

    @Test
    public void shouldSetResponseTypeIdTokenToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "id_token token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdTokenToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code id_token token"));
    }

    @Test
    public void shouldSetNonNullAuthenticationParameters() throws Exception {
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
    public void shouldBuildAuthorizeURIWithoutNulls() throws Exception {
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
    public void shouldBuildAuthorizeURIWithCorrectSchemeHostAndPath() throws Exception {
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
    public void shouldBuildAuthorizeURIWithResponseTypeIdToken() throws Exception {
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
    public void shouldBuildAuthorizeURIWithResponseTypeToken() throws Exception {
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
    public void shouldBuildAuthorizeURIWithResponseTypeCode() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .withState("a-state")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("nonce")));
        assertThat(uri, hasParamWithValue(is("code_challenge"), not(isEmptyOrNullString())));
        assertThat(uri, hasParamWithValue("code_challenge_method", "S256"));
        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldStartWithBrowserCustomTabsOptions() throws Exception {
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
    public void shouldStartWithBrowser() throws Exception {
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
    public void shouldStartWithWebViewAndDefaultConnection() throws Exception {
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
    public void shouldStartWithWebViewAndCustomConnection() throws Exception {
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

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToStartWithInvalidAuthorizeURI() throws Exception {
        Auth0 account = Mockito.mock(Auth0.class);
        when(account.getAuthorizeUrl()).thenReturn(null);

        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback);

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_authorize_url"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Auth0 authorize URL not properly set. This can be related to an invalid domain."));
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeWithRequestCodeWithResponseTypeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback, REQUEST_CODE);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        String sentNonce = uri.getQueryParameter(KEY_NONCE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(customNonceJWT(sentNonce), null, null, null, null, sentState, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeWithIntentWithResponseTypeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        String sentNonce = uri.getQueryParameter(KEY_NONCE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(customNonceJWT(sentNonce), null, null, null, null, sentState, null, null));
        assertTrue(WebAuthProvider.resume(intent));


        verify(callback).onSuccess(any(Credentials.class));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldStartWithValidRequestCode() throws Exception {
        final Credentials credentials = Mockito.mock(Credentials.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callback.onSuccess(credentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), eq(callback));

        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", null, null));
        int DEFAULT_REQUEST_CODE = 110;
        assertTrue(WebAuthProvider.resume(DEFAULT_REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeWithIntentWithCodeGrant() throws Exception {
        Date expiresAt = new Date();
        final Credentials codeCredentials = new Credentials("codeId", "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is("codeId"));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("codeAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("codeRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("codeType"));
        assertThat(credentialsCaptor.getValue().getExpiresAt(), is(expiresAt));
        assertThat(credentialsCaptor.getValue().getScope(), is("codeScope"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeWithRequestCodeWithCodeGrant() throws Exception {
        Date expiresAt = new Date();
        final Credentials codeCredentials = new Credentials("codeId", "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback, REQUEST_CODE);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is("codeId"));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("codeAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("codeRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("codeType"));
        assertThat(credentialsCaptor.getValue().getExpiresAt(), is(expiresAt));
        assertThat(credentialsCaptor.getValue().getScope(), is("codeScope"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeWithIntentWithImplicitGrant() throws Exception {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is("urlId"));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("urlAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("urlRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("urlType"));
        assertThat(credentialsCaptor.getValue().getExpiresIn(), is(1111L));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeWithRequestCodeWithImplicitGrant() throws Exception {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is("urlId"));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("urlAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("urlRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("urlType"));
        assertThat(credentialsCaptor.getValue().getExpiresIn(), is(1111L));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeWithRequestCodeWhenResultCancelled() throws Exception {
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
    public void shouldResumeWithIntentWhenResultCancelled() throws Exception {
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
    public void shouldCalculateExpiresAtDateOnResumeAuthentication() throws Exception {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        WebAuthProvider.getInstance().setCurrentTimeInMillis(CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", 1111L, sentState, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        long expirationTime = CURRENT_TIME_MS + 1111L * 1000;
        assertThat(credentialsCaptor.getValue().getExpiresAt(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getExpiresAt().getTime(), is(expirationTime));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldReThrowAnyFailedCodeExchangeDialog() throws Exception {
        final Dialog dialog = Mockito.mock(Dialog.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callbackCaptor.getValue().onFailure(dialog);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", 1111L, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(dialog);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldReThrowAnyFailedCodeExchangeException() throws Exception {
        final AuthenticationException exception = Mockito.mock(AuthenticationException.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                callbackCaptor.getValue().onFailure(exception);
                return null;
            }
        }).when(pkce).getToken(any(String.class), callbackCaptor.capture());
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", 1111L, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(exception);
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithIntentWithAccessDenied() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "access_denied", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithRequestCodeWithAccessDenied() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "access_denied", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithIntentWithRuleError() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "unauthorized", "Custom Rule Error"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("unauthorized"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Custom Rule Error"));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithRequestCodeWithRuleError() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "unauthorized", "Custom Rule Error"));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("unauthorized"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Custom Rule Error"));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithIntentWithConfigurationInvalid() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "some other error", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithRequestCodeWithConfigurationInvalid() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "some other error", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithIntentWithLoginRequired() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "login_required", "Login Required"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("login_required"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Login Required"));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithRequestCodeWithLoginRequired() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", "login_required", "Login Required"));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("login_required"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Login Required"));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithIntentWithInvalidState() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithRequestCodeWithInvalidState() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithIntentWithInvalidNonce() throws Exception {
        WebAuthProvider.init(account)
                .withState("state")
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null, null, "state", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received nonce is invalid. Try again."));
    }

    @SuppressWarnings({"deprecation", "ThrowableResultOfMethodCallIgnored"})
    @Test
    public void shouldFailToResumeWithRequestCodeWithInvalidNonce() throws Exception {
        WebAuthProvider.init(account)
                .withState("state")
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback, REQUEST_CODE);
        Intent intent = createAuthIntent(createHash("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null, null, "state", null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received nonce is invalid. Try again."));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeWithUnexpectedRequestCode() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", null, null));
        assertFalse(WebAuthProvider.resume(999, Activity.RESULT_OK, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeWithResultNotOK() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", null, null));
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, 999, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeWithIntentWithEmptyUriValues() throws Exception {
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
    public void shouldFailToResumeWithRequestCodeWithEmptyUriValues() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldFailToResumeWithIntentWithoutFirstInitProvider() throws Exception {
        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldFailToResumeWithRequestCodeWithoutFirstInitProvider() throws Exception {
        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldResumeWithIntentWithNullIntent() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback);
        assertFalse(WebAuthProvider.resume(null));
    }

    @SuppressWarnings("deprecation")
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
                .start(activity, callback);

        assertThat(WebAuthProvider.getInstance(), is(notNullValue()));
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(intent));
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldClearInstanceAfterSuccessAuthenticationWithRequestCode() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertThat(WebAuthProvider.getInstance(), is(notNullValue()));
        Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", null, "1234567890", null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @Test
    public void shouldFailToStartWithBrowserWhenNoBrowserAppIsInstalled() throws Exception {
        prepareBrowserApp(false, null);
        WebAuthProvider.init(account)
                .useBrowser(true)
                .start(activity, callback);

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.browser_not_available"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("No Browser application installed to perform web authentication."));
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldNotFailToStartWithWebviewWhenNoBrowserAppIsInstalled() throws Exception {
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

    @Test
    public void shouldHaveBrowserAppInstalled() {
        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        prepareBrowserApp(true, intentCaptor);

        boolean hasBrowserApp = WebAuthProvider.Builder.hasBrowserAppInstalled(activity.getPackageManager());
        MatcherAssert.assertThat(hasBrowserApp, Is.is(true));
        MatcherAssert.assertThat(intentCaptor.getValue(), Is.is(IntentMatchers.hasAction(Intent.ACTION_VIEW)));
        MatcherAssert.assertThat(URLUtil.isValidUrl(intentCaptor.getValue().getDataString()), Is.is(true));
    }

    @Test
    public void shouldNotHaveBrowserAppInstalled() {
        ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        prepareBrowserApp(false, intentCaptor);

        boolean hasBrowserApp = WebAuthProvider.Builder.hasBrowserAppInstalled(activity.getPackageManager());
        MatcherAssert.assertThat(hasBrowserApp, Is.is(false));
        MatcherAssert.assertThat(intentCaptor.getValue(), Is.is(IntentMatchers.hasAction(Intent.ACTION_VIEW)));
        MatcherAssert.assertThat(URLUtil.isValidUrl(intentCaptor.getValue().getDataString()), Is.is(true));
    }


    //Test Helper Functions
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
        String header = encodeString("{}");
        String bodyBuilder = "{\"nonce\":\"" + nonce + "\"}";
        String body = encodeString(bodyBuilder);
        String signature = "sign";
        return String.format("%s.%s.%s", header, body, signature);
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