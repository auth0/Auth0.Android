/*
 * Auth0Test.java
 *
 * Copyright (c) 2016 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.auth0.android;

import android.content.Context;
import android.content.res.Resources;

import com.auth0.android.util.Telemetry;
import com.squareup.okhttp.HttpUrl;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;

import static com.auth0.android.util.HttpUrlMatcher.hasHost;
import static com.auth0.android.util.HttpUrlMatcher.hasPath;
import static com.auth0.android.util.HttpUrlMatcher.hasScheme;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class Auth0Test {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();
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
        MockitoAnnotations.initMocks(this);
        when(context.getPackageName()).thenReturn(PACKAGE_NAME);
    }

    @Test
    public void shouldBeOIDCConformant() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setOIDCConformant(true);

        assertThat(auth0.isOIDCConformant(), is(true));
    }

    @Test
    public void shouldNotBeOIDCConformant() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setOIDCConformant(false);

        assertThat(auth0.isOIDCConformant(), is(false));
    }

    @Test
    public void shouldNotBeOIDCConformantByDefault() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        assertThat(auth0.isOIDCConformant(), is(false));
    }

    @Test
    public void shouldHaveLoggingEnabled() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setLoggingEnabled(true);

        assertThat(auth0.isLoggingEnabled(), is(true));
    }

    @Test
    public void shouldNotHaveLoggingEnabled() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setLoggingEnabled(false);

        assertThat(auth0.isLoggingEnabled(), is(false));
    }

    @Test
    public void shouldNotEnforceTLS12ByDefault() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        assertThat(auth0.isTLS12Enforced(), is(false));
    }

    @Test
    public void shouldHaveTLS12Enforced() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setTLS12Enforced(true);

        assertThat(auth0.isTLS12Enforced(), is(true));
    }

    @Test
    public void shouldNotHaveTLS12Enforced() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setTLS12Enforced(false);

        assertThat(auth0.isTLS12Enforced(), is(false));
    }

    @Test
    public void shouldHaveConnectTimeout() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setConnectTimeoutInSeconds(5);

        assertThat(auth0.getConnectTimeoutInSeconds(), is(5));
    }

    @Test
    public void shouldReadHaveTimeout() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setReadTimeoutInSeconds(15);

        assertThat(auth0.getReadTimeoutInSeconds(), is(15));
    }

    @Test
    public void shouldHaveWriteTimeout() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setWriteTimeoutInSeconds(20);

        assertThat(auth0.getWriteTimeoutInSeconds(), is(20));
    }

    @Test
    public void shouldNotHaveLoggingEnabledByDefault() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        assertThat(auth0.isLoggingEnabled(), is(false));
    }

    @Test
    public void shouldBuildFromResources() {
        Resources resources = Mockito.mock(Resources.class);
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq(PACKAGE_NAME))).thenReturn(222);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq(PACKAGE_NAME))).thenReturn(333);

        when(context.getString(eq(222))).thenReturn(CLIENT_ID);
        when(context.getString(eq(333))).thenReturn(DOMAIN);

        Auth0 auth0 = new Auth0(context);

        assertThat(auth0, notNullValue());
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(auth0.getDomainUrl(), equalTo("https://samples.auth0.com/"));
        assertThat(auth0.getConfigurationUrl(), equalTo("https://cdn.auth0.com/"));
    }

    @Test
    public void shouldFailToBuildFromResourcesWithoutClientID() {
        Resources resources = Mockito.mock(Resources.class);
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq(PACKAGE_NAME))).thenReturn(0);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq(PACKAGE_NAME))).thenReturn(333);

        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("The 'R.string.com_auth0_client_id' value it's not defined in your project's resources file.");

        new Auth0(context);
    }

    @Test
    public void shouldFailToBuildFromResourcesWithoutDomain() {
        Resources resources = Mockito.mock(Resources.class);
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq(PACKAGE_NAME))).thenReturn(222);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq(PACKAGE_NAME))).thenReturn(0);

        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("The 'R.string.com_auth0_domain' value it's not defined in your project's resources file.");

        new Auth0(context);
    }

    @Test
    public void shouldBuildWithClientIdAndDomain() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://cdn.auth0.com")));
    }

    @Test
    public void shouldBuildWithConfigurationDomainToo() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN, CONFIG_DOMAIN_CUSTOM);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://config.mydomain.com")));
    }

    @Test
    public void shouldHandleEUInstance() {
        Auth0 auth0 = new Auth0(CLIENT_ID, EU_DOMAIN);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.eu.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://cdn.eu.auth0.com")));
    }

    @Test
    public void shouldHandleAUInstance() {
        Auth0 auth0 = new Auth0(CLIENT_ID, AU_DOMAIN);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples.au.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://cdn.au.auth0.com")));
    }

    @Test
    public void shouldHandleOtherInstance() {
        Auth0 auth0 = new Auth0(CLIENT_ID, OTHER_DOMAIN);
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://samples-test.other-subdomain.other.auth0.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://cdn.other.auth0.com")));
    }

    @Test
    public void shouldHandleNonAuth0Domain() {
        Auth0 auth0 = new Auth0(CLIENT_ID, "mydomain.com");
        assertThat(auth0.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(auth0.getDomainUrl()), equalTo(HttpUrl.parse("https://mydomain.com")));
        assertThat(HttpUrl.parse(auth0.getConfigurationUrl()), equalTo(HttpUrl.parse("https://mydomain.com")));
    }

    @Test
    public void shouldThrowWhenInvalidDomain() {
        expectedException.expect(IllegalArgumentException.class);
        new Auth0(CLIENT_ID, "some invalid domain.com");
    }

    @Test
    public void shouldReturnAuthorizeUrl() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);

        final HttpUrl url = HttpUrl.parse(auth0.getAuthorizeUrl());
        assertThat(url, hasScheme("https"));
        assertThat(url, hasHost(DOMAIN));
        assertThat(url, hasPath("authorize"));
    }

    @Test
    public void shouldReturnLogoutUrl() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);

        final HttpUrl url = HttpUrl.parse(auth0.getLogoutUrl());
        assertThat(url, hasScheme("https"));
        assertThat(url, hasHost(DOMAIN));
        assertThat(url, hasPath("v2", "logout"));
    }

    @Test
    public void shouldNotReturnTelemetryWhenExplicitlyDisabledThem() {
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.doNotSendTelemetry();
        assertThat(auth0.getTelemetry(), is(nullValue()));
    }

    @Test
    public void shouldSetCustomTelemetry() {
        Telemetry customTelemetry = new Telemetry("custom", "9.9.9", "1.1.1");
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setTelemetry(customTelemetry);
        assertThat(auth0.getTelemetry(), is(equalTo(customTelemetry)));
    }
}