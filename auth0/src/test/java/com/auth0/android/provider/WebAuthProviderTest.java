package com.auth0.android.provider;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import android.support.annotation.Nullable;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.authentication.ParameterBuilder;
import com.auth0.android.authentication.ResponseType;
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
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static android.support.test.espresso.intent.matcher.IntentMatchers.hasAction;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasData;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasExtra;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasFlag;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasHost;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasParamWithName;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasParamWithValue;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasPath;
import static android.support.test.espresso.intent.matcher.UriMatchers.hasScheme;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
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

    private static final String CALLBACK_URL = "https://my-domain.auth0.com/android/com.auth0.android.lock.app/callback";

    private static final int REQUEST_CODE = 11;
    private static final String CONNECTION_NAME = "connection";
    private static final String SCOPE = "scope";
    private static final String[] CONNECTION_SCOPE = new String[]{"some", "connection", "scope"};
    private static final String STATE = "state";
    private static final String NONCE = "nonce";
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
    public void shouldHaveDefaultsOnInit() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.useBrowser(), is(true));
        assertThat(instance.useCodeGrant(), is(true));
        assertThat(instance.useFullscreen(), is(false));
        assertThat(instance.getConnection(), is(nullValue()));
        assertThat(instance.getScope(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getConnectionScope(), is(nullValue()));
        assertThat(instance.getState(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getNonce(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getParameters(), is(notNullValue()));
    }

    @Test
    public void shouldNotHaveDefaultConnection() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getConnection(), is(nullValue()));
    }

    @Test
    public void shouldNotHaveDefaultConnectionScope() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getConnectionScope(), is(nullValue()));
    }

    @Test
    public void shouldHaveDefaultScope() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getScope(), is(SCOPE_OPEN_ID));
    }

    @Test
    public void shouldHaveDefaultState() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getState(), is(notNullValue()));
    }

    @Test
    public void shouldHaveDefaultNonce() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getNonce(), is(notNullValue()));
    }

    @Test
    public void shouldHaveDefaultResponseType() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getResponseType(), is("code"));
    }

    @Test
    public void shouldUseCodeGrantByDefault() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.useCodeGrant(), is(true));
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
                .withConnectionScope(CONNECTION_SCOPE)
                .withState(STATE)
                .withNonce(NONCE)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.useBrowser(), is(true));
        assertThat(instance.useCodeGrant(), is(true));
        assertThat(instance.useFullscreen(), is(true));
        assertThat(instance.getConnection(), is(CONNECTION_NAME));
        assertThat(instance.getScope(), is(SCOPE));
        assertThat(instance.getConnectionScope(), is("some connection scope"));
        assertThat(instance.getState(), is(STATE));
        assertThat(instance.getNonce(), is(NONCE));
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
    public void shouldNotSetAuthenticationParametersWithNullValue() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("a", "valid");
        parameters.put("b", null);
        parameters.put("scope", null);
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));

        assertThat(intent.getData(), hasParamWithValue("a", "valid"));
        assertThat(intent.getData(), not(hasParamWithName("b")));
        assertThat(intent.getData(), hasParamWithValue("scope", SCOPE_OPEN_ID));
    }

    @Test
    public void shouldBuildAuthorizeURIWithoutNulls() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasData(hasScheme(baseUriString.getScheme())));
        assertThat(intent.getData(), hasHost(baseUriString.getHost()));
        assertThat(intent.getData(), hasPath(baseUriString.getPath()));

        Set<String> params = intent.getData().getQueryParameterNames();
        for (String p : params) {
            assertThat(intent.getData(), not(hasParamWithValue(p, null)));
            assertThat(intent.getData(), not(hasParamWithValue(p, "null")));
        }
    }

    @Test
    public void shouldBuildAuthorizeURIWithResponseTypeIdToken() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN)
                .withState("a-state")
                .withNonce("a-nonce")
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasData(hasScheme(baseUriString.getScheme())));
        assertThat(intent.getData(), hasHost(baseUriString.getHost()));
        assertThat(intent.getData(), hasPath(baseUriString.getPath()));

        assertThat(intent.getData(), not(hasParamWithName("connection")));
        assertThat(intent.getData(), hasParamWithValue("state", "a-state"));
        assertThat(intent.getData(), hasParamWithValue("nonce", "a-nonce"));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge")));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge_method")));
        assertThat(intent.getData(), hasParamWithValue("scope", "openid"));
        assertThat(intent.getData(), hasParamWithValue("client_id", "clientId"));
        assertThat(intent.getData(), hasParamWithValue("response_type", "id_token"));
        assertThat(intent.getData(), hasParamWithValue("redirect_uri", "https://domain/android/package/callback"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithResponseTypeToken() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .withState("a-state")
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasData(hasScheme(baseUriString.getScheme())));
        assertThat(intent.getData(), hasHost(baseUriString.getHost()));
        assertThat(intent.getData(), hasPath(baseUriString.getPath()));

        assertThat(intent.getData(), not(hasParamWithName("connection")));
        assertThat(intent.getData(), hasParamWithValue("state", "a-state"));
        assertThat(intent.getData(), not(hasParamWithName("nonce")));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge")));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge_method")));
        assertThat(intent.getData(), hasParamWithValue("scope", "openid"));
        assertThat(intent.getData(), hasParamWithValue("client_id", "clientId"));
        assertThat(intent.getData(), hasParamWithValue("response_type", "token"));
        assertThat(intent.getData(), hasParamWithValue("redirect_uri", "https://domain/android/package/callback"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithResponseTypeCode() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.CODE)
                .withState("a-state")
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasData(hasScheme(baseUriString.getScheme())));
        assertThat(intent.getData(), hasHost(baseUriString.getHost()));
        assertThat(intent.getData(), hasPath(baseUriString.getPath()));

        assertThat(intent.getData(), not(hasParamWithName("connection")));
        assertThat(intent.getData(), hasParamWithValue("state", "a-state"));
        assertThat(intent.getData(), not(hasParamWithName("nonce")));
        assertThat(intent.getData(), hasParamWithName("code_challenge"));
        assertThat(intent.getData(), hasParamWithValue("code_challenge_method", "S256"));
        assertThat(intent.getData(), hasParamWithValue("scope", "openid"));
        assertThat(intent.getData(), hasParamWithValue("client_id", "clientId"));
        assertThat(intent.getData(), hasParamWithValue("response_type", "code"));
        assertThat(intent.getData(), hasParamWithValue("redirect_uri", "https://domain/android/package/callback"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithCustomConnection() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .withConnection("my-connection")
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));

        assertThat(intent.getData(), hasParamWithValue("connection", "my-connection"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithCustomScope() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .withScope("openid profile contacts")
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));

        assertThat(intent.getData(), hasParamWithValue("scope", "openid profile contacts"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithCustomState() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .withState("1234567890")
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));

        assertThat(intent.getData(), hasParamWithValue("state", "1234567890"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithCustomNonce() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.ID_TOKEN) //requires nonce
                .withNonce("1234567890")
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));

        assertThat(intent.getData(), hasParamWithValue("nonce", "1234567890"));
    }

    @Test
    public void shouldBuildAuthorizeURIWithCustomParameters() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("custom_param_1", "custom_value_1");
        parameters.put("custom_param_2", "custom_value_2");
        WebAuthProvider.init(account)
                .withResponseType(ResponseType.TOKEN)
                .withConnection("my-connection")
                .withState("a-state")
                .withScope("super_scope")
                .withConnectionScope("first_connection_scope", "second_connection_scope")
                .withParameters(parameters)
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasData(hasScheme(baseUriString.getScheme())));
        assertThat(intent.getData(), hasHost(baseUriString.getHost()));
        assertThat(intent.getData(), hasPath(baseUriString.getPath()));

        assertThat(intent.getData(), hasParamWithValue("connection", "my-connection"));
        assertThat(intent.getData(), hasParamWithValue("state", "a-state"));
        assertThat(intent.getData(), hasParamWithValue("scope", "super_scope"));
        assertThat(intent.getData(), hasParamWithValue("connection_scope", "first_connection_scope second_connection_scope"));
        assertThat(intent.getData(), hasParamWithValue("client_id", "clientId"));
        assertThat(intent.getData(), hasParamWithValue("response_type", "token"));
        assertThat(intent.getData(), hasParamWithValue("redirect_uri", "https://domain/android/package/callback"));
        assertThat(intent.getData(), hasParamWithValue("custom_param_1", "custom_value_1"));
        assertThat(intent.getData(), hasParamWithValue("custom_param_2", "custom_value_2"));

        assertThat(intent.getData(), not(hasParamWithName("nonce")));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge_method")));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge")));
        assertThat(intent.getData(), not(hasParamWithValue("auth0Client", null)));
        assertThat(intent.getData(), not(hasParamWithValue("auth0Client", "null")));
    }

    @Test
    public void shouldBuildAuthorizeURIWhenNotUsingCodeGrant() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));

        assertThat(intent.getData(), hasParamWithValue("response_type", "token"));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge_method")));
        assertThat(intent.getData(), not(hasParamWithName("code_challenge")));
    }

    @Test
    public void shouldBuildAuthorizeURIWhenUsingCodeGrant() throws Exception {
        Activity activity = mock(Activity.class);
        Context appContext = mock(Context.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        when(appContext.getPackageName()).thenReturn("package");
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .start(activity, callback);

        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));

        assertThat(intent.getData(), hasParamWithValue("response_type", "code"));
        assertThat(intent.getData(), hasParamWithValue("code_challenge_method", "S256"));
        assertThat(intent.getData(), hasParamWithName("code_challenge"));
    }

    @Test
    public void shouldRespectCallOrderWhenFirstSettingScope() throws Exception {
        Context appContext = mock(Context.class);
        when(appContext.getPackageName()).thenReturn("package");
        Activity activity = mock(Activity.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("custom_param", "custom_value");
        parameters.put("scope", "default_scope");
        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());

        WebAuthProvider.init(account)
                .withScope("profile super_scope")
                .withParameters(parameters)
                .start(activity, callback);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasData(hasScheme(baseUriString.getScheme())));
        assertThat(intent.getData(), hasHost(baseUriString.getHost()));
        assertThat(intent.getData(), hasPath(baseUriString.getPath()));

        assertThat(intent.getData(), hasParamWithValue("scope", "default_scope"));
        assertThat(intent.getData(), hasParamWithValue("custom_param", "custom_value"));
    }

    @Test
    public void shouldRespectCallOrderWhenFirstSettingParameters() throws Exception {
        Context appContext = mock(Context.class);
        when(appContext.getPackageName()).thenReturn("package");
        Activity activity = mock(Activity.class);
        when(activity.getApplicationContext()).thenReturn(appContext);
        when(activity.getPackageName()).thenReturn("package");
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("custom_param", "custom_value");
        parameters.put("scope", "default_scope");
        final ArgumentCaptor<Intent> intentCaptor = ArgumentCaptor.forClass(Intent.class);
        Uri baseUriString = Uri.parse(account.getAuthorizeUrl());

        WebAuthProvider.init(account)
                .withParameters(parameters)
                .withScope("profile super_scope")
                .start(activity, callback);
        verify(activity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasData(hasScheme(baseUriString.getScheme())));
        assertThat(intent.getData(), hasHost(baseUriString.getHost()));
        assertThat(intent.getData(), hasPath(baseUriString.getPath()));

        assertThat(intent.getData(), hasParamWithValue("scope", "profile super_scope"));
        assertThat(intent.getData(), hasParamWithValue("custom_param", "custom_value"));
    }

    @Test
    public void shouldNotOverrideScopeValueWithDefaultScope() throws Exception {
        Map<String, Object> parameters = ParameterBuilder.newBuilder().setScope("openid email picture").asDictionary();
        WebAuthProvider.init(account)
                .withParameters(parameters)
                .start(activity, callback);

        final WebAuthProvider instance = WebAuthProvider.getInstance();
        assertThat(instance.getScope(), is("openid email picture"));
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
                .withNonce("1234567890")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback, REQUEST_CODE);
        final Intent intent = createAuthIntent(createHash(null, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null));
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldResumeWithIntentWithResponseTypeIdToken() throws Exception {
        WebAuthProvider.init(account)
                .withNonce("1234567890")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash(null, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null));
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
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        final int DEFAULT_REQUEST_CODE = 110;
        assertTrue(WebAuthProvider.resume(DEFAULT_REQUEST_CODE, Activity.RESULT_OK, intent));
    }

    @Test
    public void shouldResumeWithIntentWithCodeGrant() throws Exception {
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
                .withState("1234567890")
                .useCodeGrant(true)
                .withPKCE(pkce)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash("aToken", "iToken", "refresh_token", "1234567890", null));
        assertTrue(WebAuthProvider.resume(intent));

        verify(callback).onSuccess(any(Credentials.class));
    }

    @Test
    public void shouldClearInstanceAfterSuccessAuthentication() throws Exception {
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
        final PKCE pkce = Mockito.mock(PKCE.class);
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
                .start(activity, callback);
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
                .start(activity, callback);
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
                .start(activity, callback);
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
                .start(activity, callback);
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
    public void shouldFailToResumeWithIntentWithInvalidNonce() throws Exception {
        WebAuthProvider.init(account)
                .withNonce("0987654321")
                .withResponseType(ResponseType.ID_TOKEN)
                .start(activity, callback);
        final Intent intent = createAuthIntent(createHash(null, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null));
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
        final Intent intent = createAuthIntent(createHash(null, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk", null, null, null));
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
                .start(activity, callback);

        final Intent intent = createAuthIntent("");
        assertFalse(WebAuthProvider.resume(intent));
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
    public void shouldHavePKCEEnabled() throws Exception {
        WebAuthProvider.init(account)
                .useCodeGrant(true)
                .start(activity, callback);

        assertTrue(WebAuthProvider.getInstance().shouldUsePKCE());
    }

    @Test
    public void shouldHavePKCEDisabled() throws Exception {
        WebAuthProvider.init(account)
                .useCodeGrant(false)
                .start(activity, callback);

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