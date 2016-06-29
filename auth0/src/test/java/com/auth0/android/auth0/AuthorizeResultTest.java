/*
 * AuthorizeResultTest.java
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

package com.auth0.android.auth0;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class AuthorizeResultTest {

    private static final int REQUEST_CODE = 11;
    private static final int OTHER_REQUEST_CODE = 12;
    private static final String CALLBACK_URL = "https://my-domain.auth0.com/android/com.auth0.android.lock.app/callback";
    private static final String SAMPLE_HASH = "#access_token=aToken&id_token=iToken&token_type=Bearer&state=randomState";

    private Intent intent;
    private Uri validUri;

    @Before
    public void setUp() throws Exception {
        intent = new Intent();
        validUri = Uri.parse(CALLBACK_URL + SAMPLE_HASH);
    }

    @Test
    public void shouldNotBeValidForNullUri() throws Exception {
        intent.setData(null);
        AuthorizeResult authorizeResult = new AuthorizeResult(intent);

        boolean isValid = authorizeResult.isValid(REQUEST_CODE);

        MatcherAssert.assertThat(isValid, Matchers.is(false));
    }

    @Test
    public void shouldNotBeValidForOtherResult() throws Exception {
        intent.setData(validUri);
        AuthorizeResult authorizeResult = new AuthorizeResult(REQUEST_CODE, Activity.RESULT_OK, intent);

        boolean isValid = authorizeResult.isValid(OTHER_REQUEST_CODE);

        MatcherAssert.assertThat(isValid, Matchers.is(false));
    }

    @Test
    public void shouldNotBeValidForCanceledResult() throws Exception {
        intent.setData(validUri);
        AuthorizeResult authorizeResult = new AuthorizeResult(REQUEST_CODE, Activity.RESULT_CANCELED, intent);

        boolean isValid = authorizeResult.isValid(REQUEST_CODE);

        MatcherAssert.assertThat(isValid, Matchers.is(false));
    }

    @Test
    public void shouldBeValidForExpectedActivityResult() throws Exception {
        intent.setData(validUri);
        AuthorizeResult authorizeResult = new AuthorizeResult(REQUEST_CODE, Activity.RESULT_OK, intent);

        boolean isValid = authorizeResult.isValid(REQUEST_CODE);

        MatcherAssert.assertThat(isValid, Matchers.is(true));
    }

    @Test
    public void shouldBeValid() throws Exception {
        intent.setData(validUri);
        AuthorizeResult authorizeResult = new AuthorizeResult(intent);

        boolean isValid = authorizeResult.isValid(0);

        MatcherAssert.assertThat(isValid, Matchers.is(true));
    }

    @Test
    public void shouldCreateAValidResultWithOnlyTheIntent() throws Exception {
        intent.setData(validUri);
        AuthorizeResult authorizeResult = new AuthorizeResult(intent);

        assertThat(authorizeResult.getRequestCode(), Matchers.is(Matchers.equalTo(-100)));
        assertThat(authorizeResult.getResultCode(), Matchers.is(Matchers.equalTo(Activity.RESULT_OK)));
        assertThat(authorizeResult.getIntent(), Matchers.is(Matchers.equalTo(intent)));
    }
}