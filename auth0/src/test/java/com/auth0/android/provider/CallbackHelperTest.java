/*
 * CallbackHelperTest.java
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

package com.auth0.android.provider;

import com.squareup.okhttp.HttpUrl;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import static com.auth0.android.util.HttpUrlMatcher.hasHost;
import static com.auth0.android.util.HttpUrlMatcher.hasPath;
import static com.auth0.android.util.HttpUrlMatcher.hasScheme;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(RobolectricGradleTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class CallbackHelperTest {

    private static final String PACKAGE_NAME = "com.auth0.lock.android.app";
    private static final String INVALID_DOMAIN = "not.-valid-domain";
    private static final String DOMAIN = "https://my-domain.auth0.com";
    private static final String DOMAIN_WITH_TRAILING_SLASH = "https://my-domain.auth0.com/";

    private CallbackHelper helper;

    @Before
    public void setUp() throws Exception {
        helper = new CallbackHelper(PACKAGE_NAME);
    }

    @Test
    public void shouldGetCallbackURI() throws Exception {
        final HttpUrl expected = HttpUrl.parse(DOMAIN + "/android/" + PACKAGE_NAME + "/callback");
        final HttpUrl result = HttpUrl.parse(helper.getCallbackURI(DOMAIN));

        assertThat(result, hasScheme("https"));
        assertThat(result, hasHost("my-domain.auth0.com"));
        assertThat(result, hasPath("android", PACKAGE_NAME, "callback"));
        assertThat(result, equalTo(expected));
    }

    @Test
    public void shouldGetCallbackURIIfDomainEndsWithSlash() throws Exception {
        final HttpUrl expected = HttpUrl.parse(DOMAIN + "/android/" + PACKAGE_NAME + "/callback");
        final HttpUrl result = HttpUrl.parse(helper.getCallbackURI(DOMAIN_WITH_TRAILING_SLASH));

        assertThat(result, hasScheme("https"));
        assertThat(result, hasHost("my-domain.auth0.com"));
        assertThat(result, hasPath("android", PACKAGE_NAME, "callback"));
        assertThat(result, equalTo(expected));
    }

    @Test
    public void shouldGetNullCallbackURIIfInvalidDomain() throws Exception {
        String uri = helper.getCallbackURI(INVALID_DOMAIN);
        assertThat(uri, nullValue());
    }

}