package com.auth0.android;

import android.content.Context;
import android.content.res.Resources;

import com.auth0.android.util.Auth0UserAgent;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;

import okhttp3.HttpUrl;

import static com.auth0.android.util.HttpUrlMatcher.hasHost;
import static com.auth0.android.util.HttpUrlMatcher.hasPath;
import static com.auth0.android.util.HttpUrlMatcher.hasScheme;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

@RunWith(RobolectricTestRunner.class)
public class Auth0Test {

    @Mock
    public Context context;

    private static final String CLIENT_ID = "CLIENT_ID";
    private static final String PACKAGE_NAME = "com.sample.app";
    private static final String DOMAIN = "samples.auth0.com";
    private static final String CONFIG_DOMAIN_CUSTOM = "config.mydomain.com";
    private static final String EU_DOMAIN = "samples.eu.auth0.com";
    private static final String AU_DOMAIN = "samples.au.auth0.com";
    private static final String OTHER_DOMAIN = "samples-test.other-subdomain.other.auth0.com";

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        when(context.getPackageName()).thenReturn(PACKAGE_NAME);
        when(context.getString(eq(222))).thenReturn(CLIENT_ID);
        when(context.getString(eq(333))).thenReturn(DOMAIN);
    }

    @Test
    public void shouldBuildFromResources() {
        Resources resources = Mockito.mock(Resources.class);
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq(PACKAGE_NAME))).thenReturn(222);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq(PACKAGE_NAME))).thenReturn(333);

        when(context.getString(eq(222))).thenReturn(CLIENT_ID);
        when(context.getString(eq(333))).thenReturn(DOMAIN);

        Auth0 auth0 = Auth0.getInstance(context);

        assertThat(auth0, notNullValue());
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(auth0.getDomainUrl(), equalTo("https://samples.auth0.com/"));
        assertThat(auth0.getConfigurationUrl(), equalTo("https://samples.auth0.com/"));
    }

    @Test
    public void shouldFailToBuildFromResourcesWithoutClientID() {
        Assert.assertThrows("The 'R.string.com_auth0_client_id' value it's not defined in your project's resources file.", IllegalArgumentException.class, () -> {
            Resources resources = Mockito.mock(Resources.class);
            when(context.getResources()).thenReturn(resources);
            when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq(PACKAGE_NAME))).thenReturn(0);
            when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq(PACKAGE_NAME))).thenReturn(333);

            Auth0.getInstance(context);
        });
    }

    @Test
    public void shouldFailToBuildFromResourcesWithoutDomain() {
        Assert.assertThrows("The 'R.string.com_auth0_domain' value it's not defined in your project's resources file.", IllegalArgumentException.class, () -> {
            Resources resources = Mockito.mock(Resources.class);
            when(context.getResources()).thenReturn(resources);
            when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq(PACKAGE_NAME))).thenReturn(222);
            when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq(PACKAGE_NAME))).thenReturn(0);

            Auth0.getInstance(context);
        });
    }

    @Test
    public void shouldBuildWithClientIdAndDomain() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, DOMAIN, null);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://samples.auth0.com")));
    }

    @Test
    public void shouldBuildWithConfigurationDomainToo() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, DOMAIN, CONFIG_DOMAIN_CUSTOM);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://config.mydomain.com")));
    }

    @Test
    public void shouldHandleEUInstance() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, EU_DOMAIN);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.eu.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://samples.eu.auth0.com")));
    }

    @Test
    public void shouldHandleAUInstance() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, AU_DOMAIN);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.au.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://samples.au.auth0.com")));
    }

    @Test
    public void shouldHandleOtherInstance() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, OTHER_DOMAIN);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples-test.other-subdomain.other.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://samples-test.other-subdomain.other.auth0.com")));
    }

    @Test
    public void shouldHandleNonAuth0Domain() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, "mydomain.com");
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://mydomain.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://mydomain.com")));
    }

    @Test
    public void shouldThrowWhenInvalidDomain() {
        Assert.assertThrows(IllegalArgumentException.class, () -> Auth0.getInstance(CLIENT_ID, "some invalid domain.com"));
    }

    @Test
    public void shouldReturnAuthorizeUrl() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, DOMAIN);

        final HttpUrl url = HttpUrl.parse(auth0.getAuthorizeUrl());
        assertThat(url, hasScheme("https"));
        assertThat(url, hasHost(DOMAIN));
        assertThat(url, hasPath("authorize"));
    }

    @Test
    public void shouldReturnLogoutUrl() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, DOMAIN);

        final HttpUrl url = HttpUrl.parse(auth0.getLogoutUrl());
        assertThat(url, hasScheme("https"));
        assertThat(url, hasHost(DOMAIN));
        assertThat(url, hasPath("v2", "logout"));
    }

    @Test
    public void shouldSetCustomTelemetry() {
        Auth0UserAgent customAuth0UserAgent = new Auth0UserAgent("custom", "9.9.9", "1.1.1");
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, DOMAIN);
        auth0.setAuth0UserAgent(customAuth0UserAgent);
        assertThat(auth0.getAuth0UserAgent(), is(equalTo(customAuth0UserAgent)));
    }

    @Test
    public void shouldThrowWhenHttpDomainUsed() {
        Assert.assertThrows("Invalid domain url: 'http://" + DOMAIN + "'. Only HTTPS domain URLs are supported. If no scheme is passed, HTTPS will be used.", IllegalArgumentException.class, () -> Auth0.getInstance(CLIENT_ID, "http://" + DOMAIN));
    }

    @Test
    public void shouldHandleUpperCaseHttpsDomain() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, "Https://" + DOMAIN);
        assertThat(auth0.getDomainUrl(), is("https://" + DOMAIN + "/"));
    }

    @Test
    public void shouldThrowWhenHttpUppercaseDomainUsed() {
        Assert.assertThrows("Invalid domain url: 'http://" + DOMAIN + "'. Only HTTPS domain URLs are supported. If no scheme is passed, HTTPS will be used.", IllegalArgumentException.class, () -> Auth0.getInstance(CLIENT_ID, "HTTP://" + DOMAIN));
    }

    @Test
    public void shouldThrowWhenConfigDomainIsHttp() {
        Assert.assertThrows("Invalid domain url: 'http://" + OTHER_DOMAIN + "'. Only HTTPS domain URLs are supported. If no scheme is passed, HTTPS will be used.", IllegalArgumentException.class, () -> Auth0.getInstance(CLIENT_ID, DOMAIN, "HTTP://" + OTHER_DOMAIN));
    }

    @Test
    public void shouldEnsureAuthorizeUrlIsOpen() throws NoSuchMethodException {
        Method method = Auth0.class.getMethod("getAuthorizeUrl");
        Assert.assertTrue(Modifier.isPublic(method.getModifiers()));
        Assert.assertFalse(Modifier.isFinal(method.getModifiers()));
    }

    @Test
    public void shouldEnsureLogoutUrlIsOpen() throws NoSuchMethodException {
        Method method = Auth0.class.getMethod("getLogoutUrl");
        Assert.assertTrue(Modifier.isPublic(method.getModifiers()));
        Assert.assertFalse(Modifier.isFinal(method.getModifiers()));
    }

    @Test
    public void sameConfigShouldReturnSameInstance() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, DOMAIN);
        Auth0 auth0_2 = Auth0.getInstance(CLIENT_ID, DOMAIN);
        Assert.assertSame(auth0, auth0_2);
    }

    @Test
    public void differentConfigShouldReturnDifferentInstances() {
        Auth0 auth0 = Auth0.getInstance(CLIENT_ID, DOMAIN);
        Auth0 auth0_2 = Auth0.getInstance(CLIENT_ID + "2", DOMAIN + "2");
        Assert.assertNotSame(auth0, auth0_2);
    }
}