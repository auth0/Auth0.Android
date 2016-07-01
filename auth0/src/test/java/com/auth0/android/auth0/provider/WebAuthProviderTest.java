package com.auth0.android.auth0.provider;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;

import com.auth0.android.auth0.Auth0;
import com.auth0.android.auth0.provider.AuthCallback;
import com.auth0.android.auth0.provider.WebAuthProvider;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricGradleTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 18, manifest = Config.NONE)
public class WebAuthProviderTest {

    private static final String CALLBACK_URL = "https://my-domain.auth0.com/android/com.auth0.android.lock.app/callback";
    private static final String SAMPLE_HASH = "#access_token=aToken&id_token=iToken&token_type=Bearer&state=randomState";

    private static final int REQUEST_CODE = 11;
    private static final String CONNECTION_NAME = "connection";
    private static final String SCOPE = "scope";
    private static final String STATE = "state";
    private static final String DEFAULT_CONNECTION_NAME = "auth0";

    @Mock
    private AuthCallback callback;
    private Activity activity;
    private Auth0 account;


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
        assertThat(instance.getConnection(), is(DEFAULT_CONNECTION_NAME));
        assertThat(instance.getScope(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getState(), is(not(Matchers.isEmptyOrNullString())));
        assertThat(instance.getParameters(), is(notNullValue()));
        assertThat(instance.getParameters().isEmpty(), is(true));
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
    public void shouldResumeAuthentication() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);
        assertTrue(WebAuthProvider.resume(REQUEST_CODE, Activity.RESULT_OK, createValidAuthIntent()));

        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);
        assertTrue(WebAuthProvider.resume(createValidAuthIntent()));
    }

    @Test
    public void shouldCleatInstanceAfterSuccessAuthentication() throws Exception {
        WebAuthProvider.init(account)
                .start(activity, callback, REQUEST_CODE);

        assertNotNull(WebAuthProvider.getInstance());
        WebAuthProvider.resume(createValidAuthIntent());
        assertNull(WebAuthProvider.getInstance());
    }

    private Intent createValidAuthIntent() {
        Uri validUri = Uri.parse(CALLBACK_URL + SAMPLE_HASH);
        Intent intent = new Intent();
        intent.setData(validUri);
        return intent;
    }

}