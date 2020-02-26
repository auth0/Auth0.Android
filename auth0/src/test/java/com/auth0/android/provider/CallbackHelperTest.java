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

import static androidx.test.espresso.intent.matcher.UriMatchers.hasHost;
import static androidx.test.espresso.intent.matcher.UriMatchers.hasScheme;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.collection.IsMapWithSize.aMapWithSize;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

import android.net.Uri;
import java.util.List;
import java.util.Map;
import org.hamcrest.collection.IsMapWithSize;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class CallbackHelperTest {

    private static final String PACKAGE_NAME = "com.auth0.lock.android.app";
    private static final String INVALID_DOMAIN = "not.-valid-domain";
    private static final String DOMAIN = "https://my-domain.auth0.com";
    private static final String DOMAIN_WITH_TRAILING_SLASH = "https://my-domain.auth0.com/";
    private static final String DEFAULT_SCHEME = "https";

    @Test
    public void shouldGetCallbackURI() {
        final Uri expected = Uri.parse(DOMAIN + "/android/" + PACKAGE_NAME + "/callback");
        final Uri result = Uri.parse(CallbackHelper.getCallbackUri(DEFAULT_SCHEME, PACKAGE_NAME, DOMAIN));

        assertThat(result, hasScheme("https"));
        assertThat(result, hasHost("my-domain.auth0.com"));
        List<String> path = result.getPathSegments();
        assertThat(path.get(0), is("android"));
        assertThat(path.get(1), is(PACKAGE_NAME));
        assertThat(path.get(2), is("callback"));
        assertThat(result, equalTo(expected));
    }

    @Test
    public void shouldGetCallbackURIWithCustomScheme() {
        final Uri expected = Uri.parse("myapp://" + "my-domain.auth0.com" + "/android/" + PACKAGE_NAME + "/callback");
        final Uri result = Uri.parse(CallbackHelper.getCallbackUri("myapp", PACKAGE_NAME, DOMAIN));

        assertThat(result, hasScheme("myapp"));
        assertThat(result, hasHost("my-domain.auth0.com"));
        List<String> path = result.getPathSegments();
        assertThat(path.get(0), is("android"));
        assertThat(path.get(1), is(PACKAGE_NAME));
        assertThat(path.get(2), is("callback"));
        assertThat(result, equalTo(expected));
    }

    @Test
    public void shouldGetCallbackURIIfDomainEndsWithSlash() {
        final Uri expected = Uri.parse(DOMAIN + "/android/" + PACKAGE_NAME + "/callback");
        final Uri result = Uri.parse(CallbackHelper.getCallbackUri(DEFAULT_SCHEME, PACKAGE_NAME, DOMAIN_WITH_TRAILING_SLASH));

        assertThat(result, hasScheme("https"));
        assertThat(result, hasHost("my-domain.auth0.com"));
        List<String> path = result.getPathSegments();
        assertThat(path.get(0), is("android"));
        assertThat(path.get(1), is(PACKAGE_NAME));
        assertThat(path.get(2), is("callback"));
        assertThat(result, equalTo(expected));
    }

    @Test
    public void shouldGetNullCallbackURIIfInvalidDomain() {
        String uri = CallbackHelper.getCallbackUri(DEFAULT_SCHEME, PACKAGE_NAME, INVALID_DOMAIN);
        assertThat(uri, nullValue());
    }

    @Test
    public void shouldParseQueryValues() {
        String uriString = "https://lbalmaceda.auth0.com/android/com.auth0.android.lock.app/callback?code=soMec0d3ML8B&state=810132b-486aa-4aa8-1768-a1dcd3368fae";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);

        assertThat(values, is(notNullValue()));
        assertThat(values, aMapWithSize(2));
        assertThat(values, hasEntry("code", "soMec0d3ML8B"));
        assertThat(values, hasEntry("state", "810132b-486aa-4aa8-1768-a1dcd3368fae"));
    }

    @Test
    public void shouldParseFragmentValues() {
        String uriString = "https://lbalmaceda.auth0.com/android/com.auth0.android.lock.app/callback#code=soMec0d3ML8B&state=810132b-486aa-4aa8-1768-a1dcd3368fae";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);

        assertThat(values, is(notNullValue()));
        assertThat(values, aMapWithSize(2));
        assertThat(values, hasEntry("code", "soMec0d3ML8B"));
        assertThat(values, hasEntry("state", "810132b-486aa-4aa8-1768-a1dcd3368fae"));
    }

    @Test
    public void shouldReturnEmptyQueryValues() {
        String uriString = "https://lbalmaceda.auth0.com/android/com.auth0.android.lock.app/callback?";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);

        assertThat(values, is(notNullValue()));
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }

    @Test
    public void shouldReturnEmptyFragmentValues() {
        String uriString = "https://lbalmaceda.auth0.com/android/com.auth0.android.lock.app/callback#";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);

        assertThat(values, is(notNullValue()));
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }

    @Test
    public void shouldGetEmptyValuesWhenQueryOrFragmentIsMissing() {
        String uriString = "https://my.website.com/some/page";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);
        assertThat(values, notNullValue());
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }

    @Test
    public void shouldGetEmptyValuesWhenQueryIsEmpty() {
        String uriString = "https://my.website.com/some/page?";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);
        assertThat(values, notNullValue());
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }

    @Test
    public void shouldGetEmptyValuesWhenQueryBeginsWithAmpersand() {
        String uriString = "https://my.website.com/some/page?&key_without_value";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);
        assertThat(values, notNullValue());
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }

    @Test
    public void shouldGetEmptyValuesWhenFragmentIsEmpty() {
        String uriString = "https://my.website.com/some/page#";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);
        assertThat(values, notNullValue());
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }

    @Test
    public void shouldGetEmptyValuesWhenFragmentBeginsWithAmpersand() {
        String uriString = "https://my.website.com/some/page#&key_without_value";
        Uri uri = Uri.parse(uriString);
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);
        assertThat(values, notNullValue());
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }

    @Test
    public void shouldGetEmptyValuesWhenUriIsNull() {
        Uri uri = null;
        final Map<String, String> values = CallbackHelper.getValuesFromUri(uri);
        assertThat(values, notNullValue());
        assertThat(values, IsMapWithSize.<String, String>anEmptyMap());
    }
}
