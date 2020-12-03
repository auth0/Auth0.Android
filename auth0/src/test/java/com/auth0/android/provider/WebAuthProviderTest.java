package com.auth0.android.provider;

import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Bundle;

import androidx.annotation.Nullable;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;
import com.auth0.android.util.AuthCallbackMatcher;
import com.auth0.android.util.AuthenticationAPI;
import com.auth0.android.util.MockAuthCallback;

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
import org.robolectric.RobolectricTestRunner;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasFlag;
import static androidx.test.espresso.intent.matcher.UriMatchers.hasHost;
import static androidx.test.espresso.intent.matcher.UriMatchers.hasParamWithName;
import static androidx.test.espresso.intent.matcher.UriMatchers.hasParamWithValue;
import static androidx.test.espresso.intent.matcher.UriMatchers.hasPath;
import static androidx.test.espresso.intent.matcher.UriMatchers.hasScheme;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_AUDIENCE;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_BASE_DOMAIN;
import static com.auth0.android.provider.JwtTestUtils.EXPECTED_NONCE;
import static com.auth0.android.provider.JwtTestUtils.FIXED_CLOCK_CURRENT_TIME_MS;
import static com.auth0.android.provider.JwtTestUtils.createJWTBody;
import static com.auth0.android.provider.JwtTestUtils.createTestJWT;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class WebAuthProviderTest {

    private static final String KEY_STATE = "state";
    private static final String KEY_NONCE = "nonce";

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

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        activity = spy(Robolectric.buildActivity(Activity.class).get());
        account = new Auth0(EXPECTED_AUDIENCE, EXPECTED_BASE_DOMAIN);

        //Next line is needed to avoid CustomTabService from being bound to Test environment
        //noinspection WrongConstant
        doReturn(false).when(activity).bindService(any(Intent.class), any(ServiceConnection.class), anyInt());
        BrowserPickerTest.setupBrowserContext(activity, Arrays.asList("com.auth0.browser"), null, null);
    }

    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//
    //** LOG IN  FEATURE **//
    //** ** ** ** ** **  **//
    //** ** ** ** ** **  **//

    @Test
    public void shouldLoginWithAccount() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        assertNotNull(WebAuthProvider.getManagerInstance());
    }

    //scheme

    @Test
    public void shouldHaveDefaultSchemeOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("connection")));
    }

    @Test
    public void shouldSetConnectionFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection", (Object) "my-connection");
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection", "my-connection"));
    }

    @Test
    public void shouldSetConnectionOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("audience")));
    }

    @Test
    public void shouldSetAudienceFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("audience", (Object) "https://mydomain.auth0.com/myapi");
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("audience", "https://mydomain.auth0.com/myapi"));
    }

    @Test
    public void shouldSetAudienceOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "openid"));
    }

    @Test
    public void shouldSetScopeFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("scope", (Object) "openid email contacts");
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("scope", "openid email contacts"));
    }

    @Test
    public void shouldSetScopeOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("connection_scope")));
    }

    @Test
    public void shouldSetConnectionScopeFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("connection_scope", (Object) "openid,email,contacts");
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("connection_scope", "openid,email,contacts"));
    }

    @Test
    public void shouldSetConnectionScopeOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("state"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetNonNullStateOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("state", "1234567890"));
    }

    @Test
    public void shouldSetStateOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("nonce"));
    }

    @Test
    public void shouldSetNonceByDefaultIfResponseTypeIncludesIdTokenOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithName("nonce"));
    }

    @Test
    public void shouldNotSetNonceByDefaultIfResponseTypeIsTokenOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("nonce")));
    }

    @Test
    public void shouldSetNonNullNonceOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
                .start(activity, callback);
        String random1 = OAuthManager.getRandomString(null);
        String random2 = OAuthManager.getRandomString(null);

        assertThat(random1, is(notNullValue()));
        assertThat(random2, is(notNullValue()));
        assertThat(random1, is(not(equalTo(random2))));
    }

    @Test
    public void shouldNotGenerateRandomStringIfDefaultValuePresentOnLogin() {
        WebAuthProvider.login(account)
                .start(activity, callback);
        String random1 = OAuthManager.getRandomString("some");
        String random2 = OAuthManager.getRandomString("some");

        assertThat(random1, is("some"));
        assertThat(random2, is("some"));
    }

    // max_age
    @Test
    public void shouldNotSetMaxAgeByDefaultOnLogin() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, not(hasParamWithName("max_age")));
    }

    @Test
    public void shouldSetMaxAgeFromParametersOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("max_age", (Object) "09876");
        WebAuthProvider.login(account)
                .withMaxAge(12345)
                .withParameters(parameters)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("max_age", "09876"));
    }

    @Test
    public void shouldSetMaxAgeFromSetterOnLogin() {
        Map<String, Object> parameters = Collections.singletonMap("max_age", (Object) "09876");
        WebAuthProvider.login(account)
                .withParameters(parameters)
                .withMaxAge(12345)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("max_age", "12345"));
    }


    // auth0 related

    @Test
    public void shouldHaveClientIdOnLogin() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("client_id", "__test_client_id__"));
    }

    @Test
    public void shouldHaveTelemetryInfoOnLogin() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue(is("auth0Client"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldHaveRedirectUriOnLogin() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri.getQueryParameter("redirect_uri"), is("https://test.domain.com/android/com.auth0.android.auth0.test/callback"));
    }

    @Test
    public void shouldSetRedirectUriIgnoringSchemeOnLogin() {
        WebAuthProvider.login(account)
                .withScheme("https")
                .withRedirectUri("myapp://app.company.com/mobile/callback")
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri.getQueryParameter("redirect_uri"), is("myapp://app.company.com/mobile/callback"));
    }

    //response type

    @Test
    public void shouldHaveDefaultResponseTypeOnLogin() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeTokenOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "token"));
    }

    @Test
    public void shouldSetResponseTypeIdTokenOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "id_token"));
    }

    @Test
    public void shouldSetResponseTypeCodeOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeCodeTokenOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.CODE | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdTokenOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.CODE | ResponseType.ID_TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "code id_token"));
    }

    @Test
    public void shouldSetResponseTypeIdTokenTokenOnLogin() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri, hasParamWithValue("response_type", "id_token token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdTokenTokenOnLogin() {
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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
        WebAuthProvider.login(account)
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

    @Test
    public void shouldStartLoginWithBrowserCustomTabsOptions() {
        CustomTabsOptions options = CustomTabsOptions.newBuilder().build();
        WebAuthProvider.login(account)
                .withCustomTabsOptions(options)
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
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(options));
    }

    @Test
    public void shouldSetExpectedNonceWithResponseTypeIdToken() throws Exception {
        WebAuthProvider.login(account)
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

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("nonce", sentNonce);
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeLoginWithIntentWithResponseTypeIdToken() throws Exception {
        WebAuthProvider.login(account)
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

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("nonce", sentNonce);
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));


        verify(callback).onSuccess(any(Credentials.class));
    }

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

        WebAuthProvider.login(account)
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, "1234567890", null, null, "1234"));
        int DEFAULT_REQUEST_CODE = 110;
        assertTrue(WebAuthProvider.resume(intent));
    }

    @Test
    public void shouldResumeLoginWithIntentWithCodeGrant() throws Exception {
        Date expiresAt = new Date();
        PKCE pkce = Mockito.mock(PKCE.class);
        WebAuthProvider.login(account)
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
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, sentState, null, null, "1234"));

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("nonce", sentNonce);
        jwtBody.put("aud", account.getClientId());
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        final Credentials codeCredentials = new Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(eq("1234"), callbackCaptor.capture());

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

    @Test
    public void shouldResumeLoginWithIntentWithHybridGrant() throws Exception {
        Date expiresAt = new Date();
        PKCE pkce = Mockito.mock(PKCE.class);
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.CODE)
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

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("nonce", sentNonce);
        jwtBody.put("aud", account.getClientId());
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, sentState, null, null, "1234"));
        final Credentials codeCredentials = new Credentials("codeIdtoken", "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(eq("1234"), callbackCaptor.capture());

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

    @Test
    public void shouldResumeLoginWithRequestCodeWithCodeGrant() throws Exception {
        Date expiresAt = new Date();
        PKCE pkce = Mockito.mock(PKCE.class);

        WebAuthProvider.login(account)
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
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, sentState, null, null,"1234"));

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("nonce", sentNonce);
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        final Credentials codeCredentials = new Credentials(expectedIdToken, "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(eq("1234"), callbackCaptor.capture());


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

    @Test
    public void shouldNotReturnUnverifiedIdTokenWhenResponseTypeIsToken() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash("maliciuouslyPutIdToken", "urlAccess", null, "urlType", 1111L, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("urlAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getType(), is("urlType"));
        assertThat(credentialsCaptor.getValue().getExpiresIn().doubleValue(), is(closeTo(1111L, 1)));
    }

    @Test
    public void shouldResumeLoginWithIntentWithImplicitGrant() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, "urlAccess", null, "urlType", 1111L, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("urlAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getType(), is("urlType"));
        assertThat(credentialsCaptor.getValue().getExpiresIn().doubleValue(), is(closeTo(1111L, 1)));
    }

    @Test
    public void shouldResumeLoginWithRequestCodeWithImplicitGrant() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, "urlAccess", null, "urlType", 1111L, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("urlAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is(nullValue()));
        assertThat(credentialsCaptor.getValue().getType(), is("urlType"));
        assertThat(credentialsCaptor.getValue().getExpiresIn().doubleValue(), is(closeTo(1111L, 1)));
    }

    @Test
    public void shouldResumeLoginWithRequestCodeWhenResultCancelled() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        Intent intent = createAuthIntent(null);
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.authentication_canceled"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The user closed the browser app and the authentication was canceled."));
    }

    @Test
    public void shouldResumeLoginWithIntentWhenResultCancelled() {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
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
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        String sentState = uri.getQueryParameter(KEY_STATE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        Intent intent = createAuthIntent(createHash(null, "urlAccess", null, "urlType", 1111L, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        long expirationTime = FIXED_CLOCK_CURRENT_TIME_MS + 1111L * 1000;
        assertThat(credentialsCaptor.getValue().getExpiresAt(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getExpiresAt().getTime(), is(expirationTime));
    }

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
        }).when(pkce).getToken(eq("1234"), callbackCaptor.capture());
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withPKCE(pkce)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, null, null, null, 1111L, "1234567890", null, null, "1234"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(dialog);
    }

    @Test
    public void shouldReThrowAnyFailedCodeExchangeExceptionOnLoginWithCodeGrant() throws Exception {
        final AuthenticationException exception = Mockito.mock(AuthenticationException.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onFailure(exception);
                return null;
            }
        }).when(pkce).getToken(eq("1234"), callbackCaptor.capture());

        WebAuthProvider.login(account)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.CODE)
                .withPKCE(pkce)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);
        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "1234567890", null, null, "1234"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(exception);
    }

    @Test
    public void shouldReThrowAnyFailedCodeExchangeExceptionOnLoginWithHybridGrant() throws Exception {
        final AuthenticationException exception = Mockito.mock(AuthenticationException.class);
        PKCE pkce = Mockito.mock(PKCE.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onFailure(exception);
                return null;
            }
        }).when(pkce).getToken(eq("1234"), callbackCaptor.capture());

        WebAuthProvider.login(account)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.CODE)
                .withPKCE(pkce)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "1234567890", null, null, "1234"));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(exception);
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithAccessDenied() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "access_denied", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithAccessDenied() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "access_denied", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Permissions were not granted. Try again."));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithRuleError() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "unauthorized", "Custom Rule Error", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("unauthorized"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Custom Rule Error"));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithRuleError() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "unauthorized", "Custom Rule Error", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("unauthorized"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Custom Rule Error"));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithConfigurationInvalid() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "some other error", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithConfigurationInvalid() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "some other error", null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.invalid_configuration"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The application isn't configured properly for the social connection. Please check your Auth0's application configuration"));
    }

    @Test
    public void shouldFailToResumeLoginWithImplicitGrantMissingIdToken() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(authExceptionCaptor.getValue().getCause().getMessage(), is("ID token is required but missing"));
    }

    @Test
    public void shouldFailToResumeLoginWhenRSAKeyIsMissingFromJWKSet() throws Exception {
        AuthenticationAPI mockAPI = new AuthenticationAPI();
        mockAPI.willReturnEmptyJsonWebKeys();

        MockAuthCallback callback = new MockAuthCallback();

        Auth0 proxyAccount = new Auth0(EXPECTED_AUDIENCE, mockAPI.getDomain());
        WebAuthProvider.login(proxyAccount)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("iss", proxyAccount.getDomainUrl());
        String expectedIdToken = createTestJWT("RS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        mockAPI.takeRequest();

        assertThat(callback, AuthCallbackMatcher.hasError());

        AuthenticationException error = callback.getError();
        assertThat(error, is(notNullValue()));
        assertThat(error.getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(error.getCause().getMessage(), is("Could not find a public key for kid \"key123\""));

        mockAPI.shutdown();
    }

    @Test
    public void shouldFailToResumeLoginWhenJWKSRequestFails() throws Exception {
        AuthenticationAPI mockAPI = new AuthenticationAPI();
        mockAPI.willReturnInvalidRequest();

        MockAuthCallback callback = new MockAuthCallback();

        Auth0 proxyAccount = new Auth0(EXPECTED_AUDIENCE, mockAPI.getDomain());
        WebAuthProvider.login(proxyAccount)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("iss", proxyAccount.getDomainUrl());
        String expectedIdToken = createTestJWT("RS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        mockAPI.takeRequest();

        assertThat(callback, AuthCallbackMatcher.hasError());

        AuthenticationException error = callback.getError();
        assertThat(error, is(notNullValue()));
        assertThat(error.getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(error.getCause().getMessage(), is("Could not find a public key for kid \"key123\""));

        mockAPI.shutdown();
    }

    @Test
    public void shouldFailToResumeLoginWhenKeyIdIsMissingFromIdTokenHeader() throws Exception {
        AuthenticationAPI mockAPI = new AuthenticationAPI();
        mockAPI.willReturnValidJsonWebKeys();

        MockAuthCallback callback = new MockAuthCallback();

        Auth0 proxyAccount = new Auth0(EXPECTED_AUDIENCE, mockAPI.getDomain());
        WebAuthProvider.login(proxyAccount)
                .withState("1234567890")
                .withNonce("abcdefg")
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        String expectedIdToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODkifQ.PZivSuGSAWpSU62-iHwI16Po9DgO9lN7SLB3168P03wXBkue6nxbL3beq6jjW9uuhqRKfOiDtsvtr3paGXHONarPqQ1LEm4TDg8CM6AugaphH36EjEjL0zEYo0nxz9Fv1Xu9_bWSzfmLLgRefjZ5R0muV7JlyfBgtkfG0avD3PtjlNtToXX1sN9DyhgCT-STX9kSQAlk23V1XA3c8st09QgmQRgtZC3ZmTEHqq_FTmFUkVUNM6E0LbgLR7bLcOx4Xqayp1mqZxUgTg7ynHI6Ey4No-R5_twAki_BR8uG0TxqHlPxuU9QTzEvCQxrqzZZufRv_kIn2-fqrF3yr3z4Og";
        Intent intent = createAuthIntent(createHash(expectedIdToken, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        mockAPI.takeRequest();

        assertThat(callback, AuthCallbackMatcher.hasError());

        AuthenticationException error = callback.getError();
        assertThat(error, is(notNullValue()));
        assertThat(error.getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(error.getCause().getMessage(), is("Could not find a public key for kid \"null\""));

        mockAPI.shutdown();
    }

    @Test
    public void shouldResumeLoginWhenJWKSRequestSuceeds() throws Exception {
        AuthenticationAPI mockAPI = new AuthenticationAPI();
        mockAPI.willReturnValidJsonWebKeys();

        MockAuthCallback callback = new MockAuthCallback();

        Auth0 proxyAccount = new Auth0(EXPECTED_AUDIENCE, mockAPI.getDomain());
        WebAuthProvider.login(proxyAccount)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("iss", proxyAccount.getDomainUrl());
        String expectedIdToken = createTestJWT("RS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        mockAPI.takeRequest();

        assertThat(callback, AuthCallbackMatcher.hasCredentials());

        Credentials credentials = callback.getCredentials();
        assertThat(credentials.getAccessToken(), is("aToken"));
        assertThat(credentials.getIdToken(), is(expectedIdToken));

        mockAPI.shutdown();
    }

    @Test
    public void shouldResumeLoginIgnoringEmptyCustomIDTokenVerificationIssuer() throws Exception {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withIdTokenVerificationIssuer(null)
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

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("nonce", sentNonce);
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeLoginUsingCustomIDTokenVerificationIssuer() throws Exception {
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withIdTokenVerificationIssuer("https://some.different.issuer/")
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

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("nonce", sentNonce);
        jwtBody.put("iss", "https://some.different.issuer/");
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, sentState, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeLoginWithHS256WithoutCheckingSignatureWhenNonOIDCConformant() throws Exception {
        Auth0 account = new Auth0(EXPECTED_AUDIENCE, EXPECTED_BASE_DOMAIN);
        account.setOIDCConformant(false);

        WebAuthProvider.login(account)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        String expectedIdToken = createTestJWT("HS256", jwtBody);
        String[] parts = expectedIdToken.split("\\.");
        expectedIdToken = parts[0] + "." + parts[1] + ".invalid-signature";

        Intent intent = createAuthIntent(createHash(expectedIdToken, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("aToken"));
        assertThat(credentialsCaptor.getValue().getIdToken(), is(expectedIdToken));
    }

    @Test
    public void shouldResumeLoginWithRS256CheckingSignatureWhenNonOIDCConformant() throws Exception {
        AuthenticationAPI mockAPI = new AuthenticationAPI();
        mockAPI.willReturnValidJsonWebKeys();

        Auth0 proxyAccount = new Auth0(EXPECTED_AUDIENCE, mockAPI.getDomain());
        proxyAccount.setOIDCConformant(false);

        MockAuthCallback callback = new MockAuthCallback();

        WebAuthProvider.login(proxyAccount)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("iss", proxyAccount.getDomainUrl());
        String expectedIdToken = createTestJWT("RS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        mockAPI.takeRequest();

        assertThat(callback, AuthCallbackMatcher.hasCredentials());

        Credentials credentials = callback.getCredentials();
        assertThat(credentials, is(notNullValue()));
        assertThat(credentials.getAccessToken(), is("aToken"));
        assertThat(credentials.getIdToken(), is(expectedIdToken));
    }

    @Test
    public void shouldFailToResumeLoginWithHS256IdTokenAndOIDCConformantConfiguration() throws Exception {
        AuthenticationAPI mockAPI = new AuthenticationAPI();
        mockAPI.willReturnValidJsonWebKeys();

        Auth0 proxyAccount = new Auth0(EXPECTED_AUDIENCE, mockAPI.getDomain());
        proxyAccount.setOIDCConformant(true);

        MockAuthCallback callback = new MockAuthCallback();

        WebAuthProvider.login(proxyAccount)
                .withState("1234567890")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("iss", proxyAccount.getDomainUrl());
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        mockAPI.takeRequest();

        assertThat(callback, AuthCallbackMatcher.hasError());

        AuthenticationException error = callback.getError();
        assertThat(error, is(notNullValue()));
        assertThat(error.getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(error.getCause().getMessage(), is("Signature algorithm of \"HS256\" is not supported. Expected the ID token to be signed with any of [RS256]."));

        mockAPI.shutdown();
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithLoginRequired() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "login_required", "Login Required", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("login_required"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Login Required"));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithLoginRequired() {
        WebAuthProvider.login(account)
                .withState("1234567890")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", "login_required", "Login Required", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("login_required"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("Login Required"));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithInvalidState() {
        WebAuthProvider.login(account)
                .withState("abcdefghijk")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithInvalidState() {
        WebAuthProvider.login(account)
                .withState("abcdefghijk")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        Intent intent = createAuthIntent(createHash(null, "aToken", null, "urlType", 1111L, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithInvalidIdTokenWithImplicitGrant() {
        WebAuthProvider.login(account)
                .withState("state")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Intent intent = createAuthIntent(createHash("not.valid", null, null, null, null, "state", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(authExceptionCaptor.getValue().getCause().getMessage(), is("ID token could not be decoded"));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithInvalidIdTokenWithHybridGrant() {
        Date expiresAt = new Date();
        PKCE pkce = Mockito.mock(PKCE.class);
        WebAuthProvider.login(account)
                .withResponseType(ResponseType.TOKEN | ResponseType.CODE)
                .withState("state")
                .withPKCE(pkce)
                .start(activity, callback);
        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = createAuthIntent(createHash(null, "urlAccess", null, null, null, "state", null, null, "1234"));
        final Credentials codeCredentials = new Credentials("not.valid", "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                callbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(eq("1234"), callbackCaptor.capture());

        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(authExceptionCaptor.getValue().getCause().getMessage(), is("ID token could not be decoded"));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithInvalidMaxAge() throws Exception {
        WebAuthProvider.login(account)
                .withState("state")
                .withNonce(EXPECTED_NONCE)
                .withIdTokenVerificationLeeway(0)
                .withMaxAge(5) //5 secs
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        long originalClock = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
        long authTime = originalClock + 1;
        long expiredMaxAge = originalClock + 10;
        managerInstance.setCurrentTimeInMillis(expiredMaxAge * 1000);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("auth_time", authTime);
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "state", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(authExceptionCaptor.getValue().getCause().getMessage(), is("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (1567314010) is after last auth at (1567314006)"));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithInvalidNonce() throws Exception {
        WebAuthProvider.login(account)
                .withState("state")
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "state", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(authExceptionCaptor.getValue().getCause().getMessage(), is("Nonce (nonce) claim mismatch in the ID token; expected \"0987654321\", found \"" + EXPECTED_NONCE + "\""));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithInvalidNonce() throws Exception {
        WebAuthProvider.login(account)
                .withState("state")
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        String expectedIdToken = createTestJWT("HS256", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "state", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(authExceptionCaptor.getValue().getCause().getMessage(), is("Nonce (nonce) claim mismatch in the ID token; expected \"0987654321\", found \"" + EXPECTED_NONCE + "\""));
    }

    @Test
    public void shouldFailToResumeLoginWithNotSupportedSigningAlgorithm() throws Exception {
        WebAuthProvider.login(account)
                .withState("state")
                .withNonce(EXPECTED_NONCE)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        OAuthManager managerInstance = (OAuthManager) WebAuthProvider.getManagerInstance();
        managerInstance.setCurrentTimeInMillis(FIXED_CLOCK_CURRENT_TIME_MS);

        Map<String, Object> jwtBody = createJWTBody();
        jwtBody.put("iss", account.getDomainUrl());
        String expectedIdToken = createTestJWT("none", jwtBody);

        Intent intent = createAuthIntent(createHash(expectedIdToken, null, null, null, null, "state", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCause(), is(Matchers.<Throwable>instanceOf(TokenValidationException.class)));
        assertThat(authExceptionCaptor.getValue().getCause().getMessage(), is("Signature algorithm of \"none\" is not supported. Expected the ID token to be signed with any of [HS256, RS256]."));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithEmptyUriValues() {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.login(account)
                .withState("abcdefghijk")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithEmptyUriValues() {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.login(account)
                .withState("abcdefghijk")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @Test
    public void shouldFailToResumeLoginWithIntentWithoutFirstInitProvider() {
        WebAuthProvider.resetManagerInstance();

        Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
    }

    @Test
    public void shouldResumeLoginWithIntentWithNullIntent() {
        WebAuthProvider.login(account)
                .withState("abcdefghijk")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        assertFalse(WebAuthProvider.resume(null));
    }

    @Test
    public void shouldFailToResumeLoginWithRequestCodeWithNullIntent() {
        WebAuthProvider.login(account)
                .withState("abcdefghijk")
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);
        assertFalse(WebAuthProvider.resume(null));
    }

    @Test
    public void shouldClearInstanceAfterSuccessLoginWithIntent() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        assertThat(WebAuthProvider.getManagerInstance(), is(notNullValue()));
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @Test
    public void shouldClearInstanceAfterSuccessLoginWithRequestCode() {
        WebAuthProvider.login(account)
                .start(activity, callback);

        assertThat(WebAuthProvider.getManagerInstance(), is(notNullValue()));
        Intent intent = createAuthIntent(createHash(null, null, null, null, null, "1234567890", null, null, null));
        assertTrue(WebAuthProvider.resume(intent));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @Test
    public void shouldFailToStartLoginWithBrowserWhenNoCompatibleBrowserAppIsInstalled() {
        CustomTabsOptions noBrowserOptions = mock(CustomTabsOptions.class);
        when(noBrowserOptions.hasCompatibleBrowser(activity.getPackageManager())).thenReturn(false);
        WebAuthProvider.login(account)
                .withCustomTabsOptions(noBrowserOptions)
                .start(activity, callback);

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.browser_not_available"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("No compatible Browser application is installed."));
        assertThat(WebAuthProvider.getManagerInstance(), is(nullValue()));
    }

    @Test
    public void shouldNotFailToStartLoginWithWebviewWhenNoBrowserAppIsInstalled() {
        CustomTabsOptions noBrowserOptions = mock(CustomTabsOptions.class);
        when(noBrowserOptions.hasCompatibleBrowser(activity.getPackageManager())).thenReturn(false);
        WebAuthProvider.login(account)
                .start(activity, callback);

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

        assertThat(uri, hasParamWithValue("client_id", EXPECTED_AUDIENCE));
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

        assertThat(uri.getQueryParameter("returnTo"), is("https://test.domain.com/android/com.auth0.android.auth0.test/callback"));
    }

    @Test
    public void shouldSetReturnToUrlIgnoringSchemeOnLogout() {
        WebAuthProvider.logout(account)
                .withScheme("https")
                .withReturnToUrl("myapp://app.company.com/mobile/callback")
                .start(activity, voidCallback);

        verify(activity).startActivity(intentCaptor.capture());
        Uri uri = intentCaptor.getValue().getParcelableExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI);
        assertThat(uri, is(notNullValue()));

        assertThat(uri.getQueryParameter("returnTo"), is("myapp://app.company.com/mobile/callback"));
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
        assertThat(extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(notNullValue()));
    }

    @Test
    public void shouldStartLogoutWithCustomTabsOptions() {
        CustomTabsOptions options = CustomTabsOptions.newBuilder().build();
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
    public void shouldFailToStartLogoutWhenNoCompatibleBrowserAppIsInstalled() {
        CustomTabsOptions noBrowserOptions = mock(CustomTabsOptions.class);
        when(noBrowserOptions.hasCompatibleBrowser(activity.getPackageManager())).thenReturn(false);
        WebAuthProvider.logout(account)
                .withCustomTabsOptions(noBrowserOptions)
                .start(activity, voidCallback);

        verify(voidCallback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("a0.browser_not_available"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("No compatible Browser application is installed."));
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

        verify(voidCallback).onSuccess(eq(null));
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

    private String createHash(@Nullable String idToken, @Nullable String accessToken, @Nullable String refreshToken, @Nullable String tokenType, @Nullable Long expiresIn, @Nullable String state, @Nullable String error, @Nullable String errorDescription, @Nullable String pkceCode) {
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
        if (pkceCode != null) {
            hash = hash.concat("code=")
                    .concat(pkceCode)
                    .concat("&");
        }
        if (hash.endsWith("&")) {
            hash = hash.substring(0, hash.length() - 1);
        }
        return hash.length() == 1 ? "" : hash;
    }

}