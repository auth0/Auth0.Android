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
@Config(sdk = 18)
public class OAuthManagerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Mock
    Auth0 account;
    @Mock
    AuthCallback callback;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldUseBrowserByDefault() {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        assertTrue(manager.useBrowser());
    }

    @Test
    public void shouldNotUseBrowser() {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        manager.useBrowser(false);
        assertFalse(manager.useBrowser());
    }

    @Test
    public void shouldNotUseFullScreenByDefault() {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        assertFalse(manager.useFullScreen());
    }

    @Test
    public void shouldUseFullScreen() {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        manager.useFullScreen(true);
        assertTrue(manager.useFullScreen());
    }

    @Test
    public void shouldNotHaveCustomTabsOptionsByDefault() {
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        assertThat(manager.customTabsOptions(), is(nullValue()));
    }

    @Test
    public void shouldSetCustomTabsOptions() {
        CustomTabsOptions options = mock(CustomTabsOptions.class);
        OAuthManager manager = new OAuthManager(account, callback, new HashMap<String, String>());
        manager.setCustomTabsOptions(options);
        assertThat(manager.customTabsOptions(), is(options));
    }

    @Test
    public void shouldMergeCredentials() {
        Date expiresAt = new Date();
        Credentials frontChannelCredentials = new Credentials("urlId", "urlAccess", "urlType", null, expiresAt, "urlScope");
        Credentials codeExchangeCredentials = new Credentials("codeId", "codeAccess", "codeType", "codeRefresh", expiresAt, "codeScope");
        Credentials merged = OAuthManager.mergeCredentials(frontChannelCredentials, codeExchangeCredentials);

        assertThat(merged.getIdToken(), is(frontChannelCredentials.getIdToken()));
        assertThat(merged.getAccessToken(), is(codeExchangeCredentials.getAccessToken()));
        assertThat(merged.getType(), is(codeExchangeCredentials.getType()));
        assertThat(merged.getRefreshToken(), is(codeExchangeCredentials.getRefreshToken()));
        assertThat(merged.getExpiresIn(), is(codeExchangeCredentials.getExpiresIn()));
        assertThat(merged.getExpiresAt(), is(expiresAt));
        assertThat(merged.getExpiresAt(), is(codeExchangeCredentials.getExpiresAt()));
        assertThat(merged.getScope(), is(codeExchangeCredentials.getScope()));
    }

    @Test
    public void shouldPreferNonNullValuesWhenMergingCredentials() {
        Credentials urlCredentials = new Credentials("urlId", "urlAccess", "urlType", null, new Date(), "urlScope");
        Credentials codeCredentials = new Credentials(null, null, null, "codeRefresh", null, null);
        Credentials merged = OAuthManager.mergeCredentials(urlCredentials, codeCredentials);

        assertThat(merged.getIdToken(), is(urlCredentials.getIdToken()));
        assertThat(merged.getAccessToken(), is(urlCredentials.getAccessToken()));
        assertThat(merged.getType(), is(urlCredentials.getType()));
        assertThat(merged.getRefreshToken(), is(codeCredentials.getRefreshToken()));
        assertThat(merged.getExpiresIn(), is(urlCredentials.getExpiresIn()));
        assertThat(merged.getScope(), is(urlCredentials.getScope()));
        assertThat(merged.getExpiresAt(), is(urlCredentials.getExpiresAt()));
    }

    @Test
    public void shouldHaveValidState() {
        OAuthManager.assertValidState("1234567890", "1234567890");
    }

    @Test
    public void shouldHaveInvalidState() {
        exception.expect(AuthenticationException.class);
        OAuthManager.assertValidState("0987654321", "1234567890");
    }

    @Test
    public void shouldHaveInvalidStateWhenOneIsNull() {
        exception.expect(AuthenticationException.class);
        OAuthManager.assertValidState("0987654321", null);
    }
}