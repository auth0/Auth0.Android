package com.auth0.android.provider;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import android.content.Context;
import android.net.Uri;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.Callback;
import com.auth0.android.dpop.DPoP;
import com.auth0.android.dpop.DPoPException;
import com.auth0.android.request.NetworkingClient;
import com.auth0.android.result.Credentials;
import com.auth0.android.util.Auth0UserAgent;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;


@RunWith(RobolectricTestRunner.class)
public class OAuthManagerTest {

    @Mock
    private Auth0 mockAccount;
    @Mock
    private Callback<Credentials, AuthenticationException> mockCallback;
    @Mock
    private CustomTabsOptions mockCtOptions;
    @Mock
    private OAuthManagerState mockState;
    @Mock
    private PKCE mockPkce;
    @Mock
    private NetworkingClient mockNetworkingClient;
    @Mock
    private Auth0UserAgent mockUserAgent;
    @Mock
    private DPoP mockDPoP;

    @Mock
    private Context mockContext;

    @Captor
    private ArgumentCaptor<AuthenticationException> authExceptionArgumentCaptor;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        Mockito.when(mockAccount.getNetworkingClient()).thenReturn(mockNetworkingClient);
        Mockito.when(mockAccount.getClientId()).thenReturn("test-client-id");
        Mockito.when(mockAccount.getDomainUrl()).thenReturn("https://test.domain.com/");
        Mockito.when(mockAccount.getAuth0UserAgent()).thenReturn(mockUserAgent);
        Mockito.when(mockUserAgent.getValue()).thenReturn("test-user-agent/1.0");
        Mockito.when(mockState.getAuth0()).thenReturn(mockAccount);
        Mockito.when(mockState.getCtOptions()).thenReturn(mockCtOptions);
        Mockito.when(mockState.getParameters()).thenReturn(Collections.emptyMap());
        Mockito.when(mockState.getHeaders()).thenReturn(Collections.emptyMap());
        Mockito.when(mockState.getPkce()).thenReturn(mockPkce);
        Mockito.when(mockState.getIdTokenVerificationIssuer()).thenReturn("default-issuer");
        Mockito.when(mockState.getIdTokenVerificationLeeway()).thenReturn(60);
    }

    @After
    public void tearDown() {
    }

    @Test
    public void shouldHaveValidState() {
        OAuthManager.assertValidState("1234567890", "1234567890");
    }

    @Test
    public void shouldHaveInvalidState() {
        Assert.assertThrows(AuthenticationException.class, () -> OAuthManager.assertValidState("0987654321", "1234567890"));
    }

    @Test
    public void shouldHaveInvalidStateWhenOneIsNull() {
        Assert.assertThrows(AuthenticationException.class, () -> OAuthManager.assertValidState("0987654321", null));
    }

    @Test
    public void buildAuthorizeUriShouldUseDefaultUrlWhenCustomUrlIsNull() throws Exception {
        final String defaultUrl = "https://default.auth0.com/authorize";
        final Map<String, String> parameters = Collections.singletonMap("param1", "value1");
        Mockito.when(mockAccount.getAuthorizeUrl()).thenReturn(defaultUrl);
        OAuthManager manager = new OAuthManager(mockAccount, mockCallback, parameters, mockCtOptions, false, null, null);
        Uri resultUri = callBuildAuthorizeUri(manager);
        Assert.assertNotNull(resultUri);
        Assert.assertEquals("https", resultUri.getScheme());
        Assert.assertEquals("default.auth0.com", resultUri.getHost());
        Assert.assertEquals("/authorize", resultUri.getPath());
        Assert.assertEquals("value1", resultUri.getQueryParameter("param1"));
        Assert.assertNull(resultUri.getQueryParameter("dpop_jkt"));
        verify(mockAccount).getAuthorizeUrl();
    }

    @Test
    public void buildAuthorizeUriShouldUseCustomUrlWhenProvided() throws Exception {
        final String defaultUrl = "https://default.auth0.com/authorize";
        final String customUrl = "https://custom.example.com/custom_auth";
        final Map<String, String> parameters = Collections.singletonMap("param1", "value1");
        Mockito.when(mockAccount.getAuthorizeUrl()).thenReturn(defaultUrl);
        OAuthManager manager = new OAuthManager(mockAccount, mockCallback, parameters, mockCtOptions, false, customUrl, null);
        Uri resultUri = callBuildAuthorizeUri(manager);
        Assert.assertNotNull(resultUri);
        Assert.assertEquals("https", resultUri.getScheme());
        Assert.assertEquals("custom.example.com", resultUri.getHost());
        Assert.assertEquals("/custom_auth", resultUri.getPath());
        Assert.assertEquals("value1", resultUri.getQueryParameter("param1"));
        Assert.assertNull(resultUri.getQueryParameter("dpop_jkt"));
        verify(mockAccount, never()).getAuthorizeUrl();
    }

    @Test
    public void managerRestoredFromStateShouldUseRestoredCustomAuthorizeUrl() throws Exception {
        final String restoredCustomUrl = "https://restored.com/custom_auth";
        final String defaultUrl = "https://should-not-be-used.com/authorize";

        Mockito.when(mockState.getCustomAuthorizeUrl()).thenReturn(restoredCustomUrl);
        Mockito.when(mockAccount.getAuthorizeUrl()).thenReturn(defaultUrl);

        OAuthManager restoredManager = new OAuthManager(
                mockState.getAuth0(), mockCallback, mockState.getParameters(),
                mockState.getCtOptions(), false, mockState.getCustomAuthorizeUrl(), null
        );
        Uri resultUri = callBuildAuthorizeUri(restoredManager);
        Assert.assertNotNull(resultUri);
        Assert.assertEquals("https", resultUri.getScheme());
        Assert.assertEquals("restored.com", resultUri.getHost());
        Assert.assertEquals("/custom_auth", resultUri.getPath());
        verify(mockAccount, never()).getAuthorizeUrl();
    }

    @Test
    public void managerRestoredFromStateShouldHandleNullCustomAuthorizeUrl() throws Exception {
        final String defaultUrl = "https://default.auth0.com/authorize";

        Mockito.when(mockState.getCustomAuthorizeUrl()).thenReturn(null);
        Mockito.when(mockAccount.getAuthorizeUrl()).thenReturn(defaultUrl);
        OAuthManager restoredManager = new OAuthManager(
                mockState.getAuth0(), mockCallback, mockState.getParameters(),
                mockState.getCtOptions(), false, mockState.getCustomAuthorizeUrl(), null
        );
        Uri resultUri = callBuildAuthorizeUri(restoredManager);
        Assert.assertNotNull(resultUri);
        Assert.assertEquals("https", resultUri.getScheme());
        Assert.assertEquals("default.auth0.com", resultUri.getHost());
        Assert.assertEquals("/authorize", resultUri.getPath());
        verify(mockAccount).getAuthorizeUrl();
    }

    private Uri callBuildAuthorizeUri(OAuthManager instance) throws Exception {
        Method method = OAuthManager.class.getDeclaredMethod("buildAuthorizeUri");
        method.setAccessible(true);
        return (Uri) method.invoke(instance);
    }

}