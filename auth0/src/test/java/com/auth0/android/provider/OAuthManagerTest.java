package com.auth0.android.provider;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Date;
import java.util.HashMap;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;


@RunWith(RobolectricTestRunner.class)
@Config(sdk = 18, manifest = Config.NONE)
public class OAuthManagerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Mock
    Auth0 account;
    @Mock
    AuthCallback callback;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldUseBrowserByDefault() throws Exception {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        assertTrue(manager.useBrowser());
    }

    @Test
    public void shouldNotUseBrowser() throws Exception {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        manager.useBrowser(false);
        assertFalse(manager.useBrowser());
    }

    @Test
    public void shouldNotUseFullScreenByDefault() throws Exception {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        assertFalse(manager.useFullScreen());
    }

    @Test
    public void shouldUseFullScreen() throws Exception {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        manager.useFullScreen(true);
        assertTrue(manager.useFullScreen());
    }

    @Test
    public void shouldNotHaveCustomTabsOptionsByDefault() throws Exception {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        assertThat(manager.customTabsOptions(), is(nullValue()));
    }

    @Test
    public void shouldSetCustomTabsOptions() throws Exception {
        CustomTabsOptions options = mock(CustomTabsOptions.class);
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        manager.setCustomTabsOptions(options);
        assertThat(manager.customTabsOptions(), is(options));
    }

    @Test
    public void shouldMergeCredentials() throws Exception {
        Date expiresAt = new Date();
        Credentials urlCredentials = new Credentials("urlId", "urlAccess", "urlType", "urlRefresh", expiresAt, "urlScope");
        Credentials codeCredentials = new Credentials("codeId", "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Credentials merged = OAuthManager.mergeCredentials(urlCredentials, codeCredentials);

        assertThat(merged.getIdToken(), is(codeCredentials.getIdToken()));
        assertThat(merged.getAccessToken(), is(codeCredentials.getAccessToken()));
        assertThat(merged.getType(), is(codeCredentials.getType()));
        assertThat(merged.getRefreshToken(), is(codeCredentials.getRefreshToken()));
        assertThat(merged.getExpiresIn(), is(codeCredentials.getExpiresIn()));
        assertThat(merged.getExpiresAt(), is(expiresAt));
        assertThat(merged.getExpiresAt(), is(codeCredentials.getExpiresAt()));
        assertThat(merged.getScope(), is(codeCredentials.getScope()));
    }

    @Test
    @SuppressWarnings("ConstantConditions")
    public void shouldPreferNonNullValuesWhenMergingCredentials() throws Exception {
        Credentials urlCredentials = new Credentials("urlId", "urlAccess", "urlType", "urlRefresh", new Date(), "urlScope");
        Credentials codeCredentials = new Credentials(null, null, null, null, null, null);
        Credentials merged = OAuthManager.mergeCredentials(urlCredentials, codeCredentials);

        assertThat(merged.getIdToken(), is(urlCredentials.getIdToken()));
        assertThat(merged.getAccessToken(), is(urlCredentials.getAccessToken()));
        assertThat(merged.getType(), is(urlCredentials.getType()));
        assertThat(merged.getRefreshToken(), is(urlCredentials.getRefreshToken()));
        assertThat(merged.getExpiresIn(), is(urlCredentials.getExpiresIn()));
        assertThat(merged.getScope(), is(urlCredentials.getScope()));
        assertThat(merged.getExpiresAt(), is(urlCredentials.getExpiresAt()));
    }

    @Test
    public void shouldHaveValidState() throws Exception {
        OAuthManager.assertValidState("1234567890", "1234567890");
    }

    @Test
    public void shouldHaveInvalidState() throws Exception {
        exception.expect(AuthenticationException.class);
        OAuthManager.assertValidState("0987654321", "1234567890");
    }

    @Test
    public void shouldHaveInvalidStateWhenOneIsNull() throws Exception {
        exception.expect(AuthenticationException.class);
        OAuthManager.assertValidState("0987654321", null);
    }

    @Test
    public void shouldHaveValidNonce() throws Exception {
        OAuthManager.assertValidNonce("1234567890", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk");
    }

    @Test
    public void shouldHaveInvalidNonce() throws Exception {
        exception.expect(AuthenticationException.class);
        OAuthManager.assertValidNonce("0987654321", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk");
    }

    @Test
    public void shouldHaveInvalidNonceOnDecodeException() throws Exception {
        exception.expect(AuthenticationException.class);
        OAuthManager.assertValidNonce("0987654321", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC.eyJub25jZSI6IjEyMzQ1Njc4OTAifQ.oUb6xFIEPJQrFbel_Js4SaOwpFfM_kxHxI7xDOHgghk");
    }

}