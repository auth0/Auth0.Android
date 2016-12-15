package com.auth0.android.provider;

import android.app.Activity;
import android.app.Dialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;

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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import edu.emory.mathcs.backport.java.util.Collections;

import static android.support.test.espresso.intent.matcher.IntentMatchers.hasAction;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasExtra;
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
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 18, manifest = Config.NONE)
public class WebAuthProviderTest {

    private static final int REQUEST_CODE = 11;
    private static final String KEY_STATE = "state";
    private static final String KEY_NONCE = "nonce";

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

    @Test
    public void shouldNotResumeWhenNotInit() throws Exception {
        Intent intentMock = Mockito.mock(Intent.class);

        assertFalse(WebAuthProvider.resume(intentMock));
        assertFalse(WebAuthProvider.resume(0, 0, intentMock));
    }

    //logging
    public void shouldHaveLoggingDisabledByDefault() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertFalse(instance.isLoggingEnabled());
    }

    @Test
    public void shouldEnableLogging() throws Exception {
        WebAuthProvider.init(account)
                .enableLogging()
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertTrue(instance.isLoggingEnabled());
    }

    //scheme

    @Test
    public void shouldHaveDefaultScheme() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithName("redirect_uri"));
        Uri redirectUri = Uri.parse(uri.getQueryParameter("redirect_uri"));
        assertThat(redirectUri, hasScheme("https"));
    }

    @Test
    public void shouldSetScheme() throws Exception {
        WebAuthProvider.init(account)
                .withScheme("myapp")
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithName("redirect_uri"));
        Uri redirectUri = Uri.parse(uri.getQueryParameter("redirect_uri"));
        assertThat(redirectUri, hasScheme("myapp"));
    }

    //connection

    @Test
    public void shouldNotHaveDefaultConnection() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, not(hasParamWithName("connection")));
    }

    @Test
    public void shouldSetConnectionFromParameters() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("connection", "my-connection");
        WebAuthProvider.init(account)
                .withConnection("some-connection")
                .withParameters(parameters)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection", "my-connection"));
    }

    @Test
    public void shouldSetConnectionFromSetter() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("connection", "my-connection");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withConnection("some-connection")
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection", "some-connection"));
    }

    @Test
    public void shouldNotOverrideConnectionValueWithDefaultConnection() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("connection", "my-connection");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection", "my-connection"));
    }

    @Test
    public void shouldSetConnection() throws Exception {
        WebAuthProvider.init(account)
                .withConnection("some-connection")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection", "some-connection"));
    }

    //audience

    @Test
    public void shouldNotHaveDefaultAudience() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, not(hasParamWithName("audience")));
    }

    @Test
    public void shouldSetAudienceFromParameters() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("audience", "https://mydomain.auth0.com/myapi");
        WebAuthProvider.init(account)
                .withAudience("https://google.com/apis")
                .withParameters(parameters)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("audience", "https://mydomain.auth0.com/myapi"));
    }

    @Test
    public void shouldSetAudienceFromSetter() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("audience", "https://mydomain.auth0.com/myapi");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withAudience("https://google.com/apis")
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("audience", "https://google.com/apis"));
    }

    @Test
    public void shouldNotOverrideAudienceValueWithDefaultAudience() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("audience", "https://mydomain.auth0.com/myapi");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("audience", "https://mydomain.auth0.com/myapi"));
    }

    @Test
    public void shouldSetAudience() throws Exception {
        WebAuthProvider.init(account)
                .withAudience("https://google.com/apis")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("audience", "https://google.com/apis"));
    }


    //scope

    @Test
    public void shouldHaveDefaultScope() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("scope", "openid"));
    }

    @Test
    public void shouldSetScopeFromParameters() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("scope", "openid email contacts");
        WebAuthProvider.init(account)
                .withScope("profile super_scope")
                .withParameters(parameters)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("scope", "openid email contacts"));
    }

    @Test
    public void shouldSetScopeFromSetter() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("scope", "openid email contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withScope("profile super_scope")
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("scope", "profile super_scope"));
    }

    @Test
    public void shouldNotOverrideScopeValueWithDefaultScope() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("scope", "openid email contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("scope", "openid email contacts"));
    }

    @Test
    public void shouldSetScope() throws Exception {
        WebAuthProvider.init(account)
                .withScope("profile super_scope")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("scope", "profile super_scope"));
    }


    //connection scope

    @Test
    public void shouldNotHaveDefaultConnectionScope() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, not(hasParamWithName("connection_scope")));
    }

    @Test
    public void shouldSetConnectionScopeFromParameters() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("connection_scope", "openid email contacts");
        WebAuthProvider.init(account)
                .withConnectionScope("profile super_scope")
                .withParameters(parameters)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection_scope", "openid email contacts"));
    }

    @Test
    public void shouldSetConnectionScopeFromSetter() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("connection_scope", "openid email contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withConnectionScope("profile super_scope")
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection_scope", "profile super_scope"));
    }

    @Test
    public void shouldNotOverrideConnectionScopeValueWithDefaultConnectionScope() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("connection_scope", "openid email contacts");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection_scope", "openid email contacts"));
    }

    @Test
    public void shouldSetConnectionScope() throws Exception {
        WebAuthProvider.init(account)
                .withConnectionScope("the", "scope", "of", "my", "connection")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("connection_scope", "the scope of my connection"));
    }


    //state

    @Test
    public void shouldHaveDefaultState() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue(is("state"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetStateFromParameters() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("state", "1234567890");
        WebAuthProvider.init(account)
                .withState("abcdefg")
                .withParameters(parameters)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("state", "1234567890"));
    }

    @Test
    public void shouldSetStateFromSetter() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("state", "1234567890");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withState("abcdefg")
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("state", "abcdefg"));
    }

    @Test
    public void shouldNotOverrideStateValueWithDefaultState() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("state", "1234567890");
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("state", "1234567890"));
    }

    @Test
    public void shouldSetState() throws Exception {
        WebAuthProvider.init(account)
                .withState("abcdefg")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("state", "abcdefg"));
    }

    //nonce

    @Test
    public void shouldNotSetNonceByDefaultIfResponseTypeIsCode() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, not(hasParamWithName("nonce")));
    }

    @Test
    public void shouldNotSetNonceByDefaultIfResponseTypeIsToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, not(hasParamWithName("nonce")));
    }

    @Test
    public void shouldHaveDefaultNonce() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue(is("nonce"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldSetUserNonceIfResponseTypeIsToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .withNonce("1234567890")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetUserNonceIfResponseTypeIsCode() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .withNonce("1234567890")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetNonceFromParameters() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("nonce", "1234567890");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withNonce("abcdefg")
                .withParameters(parameters)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetNonceFromSetter() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("nonce", "1234567890");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withParameters(parameters)
                .withNonce("abcdefg")
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("nonce", "abcdefg"));
    }

    @Test
    public void shouldNotOverrideNonceValueWithDefaultNonce() throws Exception {
        Map<String, Object> parameters = Collections.singletonMap("nonce", "1234567890");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldSetNonce() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withNonce("abcdefg")
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("nonce", "abcdefg"));
    }

    @Test
    public void shouldGenerateRandomStringIfDefaultValueMissing() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);
        String random1 = WebAuthProvider.getInstance().getRandomString(null);
        String random2 = WebAuthProvider.getInstance().getRandomString(null);

        assertThat(random1, is(notNullValue()));
        assertThat(random2, is(notNullValue()));
        assertThat(random1, is(not(equalTo(random2))));
    }

    @Test
    public void shouldNotGenerateRandomStringIfDefaultValuePresent() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);
        String random1 = WebAuthProvider.getInstance().getRandomString("some");
        String random2 = WebAuthProvider.getInstance().getRandomString("some");

        assertThat(random1, is("some"));
        assertThat(random2, is("some"));
    }


    // auth0 related

    @Test
    public void shouldHaveClientId() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("client_id", "clientId"));
    }

    @Test
    public void shouldHaveTelemetryInfo() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue(is("auth0Client"), not(isEmptyOrNullString())));
    }

    @Test
    public void shouldHaveRedirectUri() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("redirect_uri", "https://domain/android/com.auth0.android.auth0/callback"));
    }

    //response type

    @Test
    public void shouldHaveDefaultResponseType() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("response_type", "token"));
    }

    @Test
    public void shouldSetResponseTypeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("response_type", "id_token"));
    }

    @Test
    public void shouldSetResponseTypeCode() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldSetResponseTypeCodeToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.TOKEN)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("response_type", "code token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.ID_TOKEN)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("response_type", "code id_token"));
    }

    @Test
    public void shouldSetResponseTypeIdTokenToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("response_type", "id_token token"));
    }

    @Test
    public void shouldSetResponseTypeCodeIdTokenToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE | ResponseType.ID_TOKEN | ResponseType.TOKEN)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

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

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, hasParamWithValue("a", "valid"));
        assertThat(uri, not(hasParamWithName("b")));
    }

    @Test
    public void shouldBuildAuthorizeURIWithoutNulls() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

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
        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

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

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

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

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

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

        WebAuthProvider provider = WebAuthProvider.getInstance();
        Uri uri = provider.buildAuthorizeUri();

        assertThat(uri, not(hasParamWithName("nonce")));
        assertThat(uri, hasParamWithValue(is("code_challenge"), not(isEmptyOrNullString())));
        assertThat(uri, hasParamWithValue("code_challenge_method", "S256"));
        assertThat(uri, hasParamWithValue("response_type", "code"));
    }

    @Test
    public void shouldStartWithBrowser() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .useBrowser(true)
                .useCodeGrant(false)
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        assertThat(intentCaptor.getValue(), is(notNullValue()));
        assertThat(intentCaptor.getValue(), hasAction(Intent.ACTION_VIEW));
        assertThat(intentCaptor.getValue(), hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY));
    }

    @Test
    public void shouldStartWithWebViewAndDefaultConnection() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .useBrowser(false)
                .useCodeGrant(false)
                .useFullscreen(false)
                .start(activity, callback, REQUEST_CODE);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivityForResult(intentCaptor.capture(), any(Integer.class));

        final ComponentName expComponent = new ComponentName("package", WebAuthActivity.class.getName());
        assertThat(intentCaptor.getValue(), is(notNullValue()));
        assertThat(intentCaptor.getValue(), hasComponent(expComponent));
        assertThat(intentCaptor.getValue(), hasExtra(WebAuthActivity.CONNECTION_NAME_EXTRA, null));
        assertThat(intentCaptor.getValue(), hasExtra(WebAuthActivity.FULLSCREEN_EXTRA, false));
    }

    @Test
    public void shouldStartWithWebViewAndCustomConnection() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .useBrowser(false)
                .withConnection("my-connection")
                .useCodeGrant(false)
                .useFullscreen(true)
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivityForResult(intentCaptor.capture(), any(Integer.class));

        final ComponentName expComponent = new ComponentName("package", WebAuthActivity.class.getName());
        assertThat(intentCaptor.getValue(), is(notNullValue()));
        assertThat(intentCaptor.getValue(), hasComponent(expComponent));
        assertThat(intentCaptor.getValue(), hasExtra(WebAuthActivity.CONNECTION_NAME_EXTRA, "my-connection"));
        assertThat(intentCaptor.getValue(), hasExtra(WebAuthActivity.FULLSCREEN_EXTRA, true));
    }

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

    @Test
    public void shouldResumeWithRequestCodeWithResponseTypeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback, REQUEST_CODE);

        String sentState = WebAuthProvider.getInstance().getParameters().get(KEY_STATE);
        String sentNonce = WebAuthProvider.getInstance().getParameters().get(KEY_NONCE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));
        final Intent intent = createAuthIntent(createHash(customNonceJWT(sentNonce), null, null, null, sentState, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeWithIntentWithResponseTypeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);

        String sentState = WebAuthProvider.getInstance().getParameters().get(KEY_STATE);

        String sentNonce = WebAuthProvider.getInstance().getParameters().get(KEY_NONCE);
        assertThat(sentState, is(not(isEmptyOrNullString())));
        assertThat(sentNonce, is(not(isEmptyOrNullString())));
        final Intent intent = createAuthIntent(createHash(customNonceJWT(sentNonce), null, null, null, sentState, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldStartWithValidRequestCode() throws Exception {
        final Credentials credentials = Mockito.mock(Credentials.class);
        final PKCE pkce = Mockito.mock(PKCE.class);
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
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
        final int DEFAULT_REQUEST_CODE = 110;
        assertTrue(WebAuthProvider.resume(DEFAULT_REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldResumeWithIntentWithCodeGrant() throws Exception {
        final Credentials codeCredentials = new Credentials("codeId", "codeAccess", "codeType", "codeRefresh");
        final PKCE pkce = Mockito.mock(PKCE.class);
        final ArgumentCaptor<AuthCallback> codeCallbackCaptor = ArgumentCaptor.forClass(AuthCallback.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                codeCallbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), codeCallbackCaptor.capture());
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);

        String sentState = WebAuthProvider.getInstance().getParameters().get(KEY_STATE);

        assertThat(sentState, is(not(isEmptyOrNullString())));
        final Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", sentState, null));
        assertTrue(WebAuthProvider.resume(intent));

        final ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is("codeId"));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("codeAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("codeRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("codeType"));
    }

    @Test
    public void shouldResumeWithRequestCodeWithCodeGrant() throws Exception {
        final Credentials codeCredentials = new Credentials("codeId", "codeAccess", "codeType", "codeRefresh");
        final PKCE pkce = Mockito.mock(PKCE.class);
        final ArgumentCaptor<AuthCallback> codeCallbackCaptor = ArgumentCaptor.forClass(AuthCallback.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                codeCallbackCaptor.getValue().onSuccess(codeCredentials);
                return null;
            }
        }).when(pkce).getToken(any(String.class), codeCallbackCaptor.capture());
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback, REQUEST_CODE);

        String sentState = WebAuthProvider.getInstance().getParameters().get(KEY_STATE);

        assertThat(sentState, is(not(isEmptyOrNullString())));
        final Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", sentState, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        final ArgumentCaptor<Credentials> credentialsCaptor = ArgumentCaptor.forClass(Credentials.class);
        verify(callback).onSuccess(credentialsCaptor.capture());

        assertThat(credentialsCaptor.getValue(), is(notNullValue()));
        assertThat(credentialsCaptor.getValue().getIdToken(), is("codeId"));
        assertThat(credentialsCaptor.getValue().getAccessToken(), is("codeAccess"));
        assertThat(credentialsCaptor.getValue().getRefreshToken(), is("codeRefresh"));
        assertThat(credentialsCaptor.getValue().getType(), is("codeType"));
    }

    @Test
    public void shouldResumeWithIntentWithImplicitGrant() throws Exception {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        String sentState = WebAuthProvider.getInstance().getParameters().get(KEY_STATE);

        assertThat(sentState, is(not(isEmptyOrNullString())));
        final Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", sentState, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeWithRequestCodeWithImplicitGrant() throws Exception {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        String sentState = WebAuthProvider.getInstance().getParameters().get(KEY_STATE);

        assertThat(sentState, is(not(isEmptyOrNullString())));
        final Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", sentState, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldReThrowAnyFailedCodeExchangeDialog() throws Exception {
        final Dialog dialog = Mockito.mock(Dialog.class);
        final PKCE pkce = Mockito.mock(PKCE.class);
        final ArgumentCaptor<AuthCallback> codeCallbackCaptor = ArgumentCaptor.forClass(AuthCallback.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                codeCallbackCaptor.getValue().onFailure(dialog);
                return null;
            }
        }).when(pkce).getToken(any(String.class), codeCallbackCaptor.capture());
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", "1234567890", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(dialog);
    }

    @Test
    public void shouldReThrowAnyFailedCodeExchangeException() throws Exception {
        final AuthenticationException exception = Mockito.mock(AuthenticationException.class);
        final PKCE pkce = Mockito.mock(PKCE.class);
        final ArgumentCaptor<AuthCallback> codeCallbackCaptor = ArgumentCaptor.forClass(AuthCallback.class);
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                codeCallbackCaptor.getValue().onFailure(exception);
                return null;
            }
        }).when(pkce).getToken(any(String.class), codeCallbackCaptor.capture());
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("urlId", "urlAccess", "urlRefresh", "urlType", "1234567890", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(exception);
    }

    @Test
    public void shouldFailToResumeWithIntentWithAccessDenied() throws Exception {
        WebAuthProvider.init(account)
                .withState("1234567890")
                .useCodeGrant(false)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", "access_denied"));
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
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", "access_denied"));
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
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", "some other error"));
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
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", "some other error"));
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
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
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
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received state is invalid. Try again."));
    }

    @Test
    public void shouldFailToResumeWithIntentWithInvalidNonce() throws Exception {
        WebAuthProvider.init(account)
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null, null, null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received nonce is invalid. Try again."));
    }

    @Test
    public void shouldFailToResumeWithRequestCodeWithInvalidNonce() throws Exception {
        WebAuthProvider.init(account)
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onFailure(authExceptionCaptor.capture());

        assertThat(authExceptionCaptor.getValue(), is(notNullValue()));
        assertThat(authExceptionCaptor.getValue().getCode(), is("access_denied"));
        assertThat(authExceptionCaptor.getValue().getDescription(), is("The received nonce is invalid. Try again."));
    }

    @Test
    public void shouldFailToResumeWithUnexpectedRequestCode() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
        assertFalse(WebAuthProvider.resume(999, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldFailToResumeWithResultCancelled() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_CANCELED, intent));
    }

    @Test
    public void shouldFailToResumeWithResultNotOK() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback, REQUEST_CODE);

        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
        assertFalse(WebAuthProvider.resume(REQUEST_CODE, 999, intent));
    }

    @Test
    public void shouldFailToResumeWithIntentWithEmptyUriValues() throws Exception {
        verifyNoMoreInteractions(callback);
        WebAuthProvider.init(account)
                .withState("abcdefghijk")
                .useCodeGrant(false)
                .start(activity, callback);

        final Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
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
                .start(activity, callback);
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
                .start(activity, callback);

        assertThat(WebAuthProvider.getInstance(), is(notNullValue()));
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(intent));
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @Test
    public void shouldClearInstanceAfterSuccessAuthenticationWithRequestCode() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertThat(WebAuthProvider.getInstance(), is(notNullValue()));
        final Intent intent = createAuthIntent(createHash("iToken", "aToken", null, "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));
        assertThat(WebAuthProvider.getInstance(), is(nullValue()));
    }

    @Test
    public void shouldMergeCredentials() throws Exception {
        Credentials urlCredentials = new Credentials("urlId", "urlAccess", "urlType", "urlRefresh");
        Credentials codeCredentials = new Credentials("codeId", "codeAccess", "codeType", "codeRefresh");
        Credentials merged = WebAuthProvider.mergeCredentials(urlCredentials, codeCredentials);

        assertThat(merged.getIdToken(), is(codeCredentials.getIdToken()));
        assertThat(merged.getAccessToken(), is(codeCredentials.getAccessToken()));
        assertThat(merged.getType(), is(codeCredentials.getType()));
        assertThat(merged.getRefreshToken(), is(codeCredentials.getRefreshToken()));
    }

    @Test
    public void shouldPreferNonNullValuesWhenMergingCredentials() throws Exception {
        Credentials urlCredentials = new Credentials("urlId", "urlAccess", "urlType", "urlRefresh");
        Credentials codeCredentials = new Credentials(null, null, null, null);
        Credentials merged = WebAuthProvider.mergeCredentials(urlCredentials, codeCredentials);

        assertThat(merged.getIdToken(), is(urlCredentials.getIdToken()));
        assertThat(merged.getAccessToken(), is(urlCredentials.getAccessToken()));
        assertThat(merged.getType(), is(urlCredentials.getType()));
        assertThat(merged.getRefreshToken(), is(urlCredentials.getRefreshToken()));
    }

    @Test
    public void shouldHaveValidNonce() throws Exception {
        assertTrue(WebAuthProvider.hasValidNonce("1234567890", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk"));
    }

    @Test
    public void shouldHaveInvalidNonce() throws Exception {
        assertFalse(WebAuthProvider.hasValidNonce("0987654321", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk"));
    }

    @Test
    public void shouldHaveInvalidNonceOnDecodeException() throws Exception {
        assertFalse(WebAuthProvider.hasValidNonce("0987654321", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk"));
    }


    //Test Helper Functions
    private Intent createAuthIntent(String hash) {
        Uri validUri = Uri.parse("https://domain.auth0.com/android/package/callback" + hash);
        Intent intent = new Intent();
        intent.setData(validUri);
        return intent;
    }

    private String createHash(@Nullable String idToken, @Nullable String accessToken, @Nullable String refreshToken, @Nullable String tokenType, @Nullable String state, @Nullable String error) {
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
        if (refreshToken != null) {
            if (!hash.endsWith("&")) {
                hash = hash.concat("&");
            }
            hash = hash.concat("refresh_token=" + refreshToken);
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