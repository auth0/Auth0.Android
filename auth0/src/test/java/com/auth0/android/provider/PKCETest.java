/*
 * PKCETest.java
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

import com.auth0.android.auth0.R;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.authentication.request.TokenRequest;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.result.Credentials;

import org.hamcrest.CoreMatchers;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;

@RunWith(RobolectricGradleTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 18, manifest = Config.NONE)
public class PKCETest {

    private static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String REDIRECT_URI = "redirectUri";
    private static final String AUTHORIZATION_CODE = "authorizationCode";

    private PKCE pkce;
    @Mock
    private AuthenticationAPIClient apiClient;
    @Mock
    private AuthCallback callback;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        pkce = new PKCE(apiClient, REDIRECT_URI, CODE_VERIFIER);
    }

    @Test
    public void shouldGenerateChallengeFromRandomVerifier() throws Exception {
        PKCE pkce = new PKCE(apiClient, REDIRECT_URI);
        assertThat(pkce.getCodeChallenge(), is(notNullValue()));
    }

    @Test
    public void shouldGenerateValidRandomCodeChallenge() throws Exception {
        PKCE randomPKCE = new PKCE(apiClient, REDIRECT_URI);
        String challenge = randomPKCE.getCodeChallenge();
        assertThat(challenge, is(notNullValue()));
        assertThat(challenge, CoreMatchers.not(Matchers.isEmptyString()));
        assertThat(challenge, not(containsString("=")));
        assertThat(challenge, not(containsString("+")));
        assertThat(challenge, not(containsString("/")));
    }

    @Test
    public void shouldGenerateExpectedCodeChallenge() throws Exception {
        String challenge = pkce.getCodeChallenge();
        assertThat(challenge, is(equalTo(CODE_CHALLENGE)));
    }

    @Test
    public void shouldGetToken() throws Exception {
        TokenRequest tokenRequest = Mockito.mock(TokenRequest.class);
        Mockito.when(apiClient.token(AUTHORIZATION_CODE, REDIRECT_URI)).thenReturn(tokenRequest);
        Mockito.when(tokenRequest.setCodeVerifier(CODE_VERIFIER)).thenReturn(tokenRequest);
        pkce.getToken(AUTHORIZATION_CODE, callback);
        Mockito.verify(apiClient).token(AUTHORIZATION_CODE, REDIRECT_URI);
        Mockito.verify(tokenRequest).setCodeVerifier(CODE_VERIFIER);
        ArgumentCaptor<BaseCallback> callbackCaptor = ArgumentCaptor.forClass(BaseCallback.class);
        Mockito.verify(tokenRequest).start(callbackCaptor.capture());
        Credentials credentials = Mockito.mock(Credentials.class);
        callbackCaptor.getValue().onSuccess(credentials);
        Mockito.verify(callback).onSuccess(credentials);
    }

    @Test
    public void shouldFailToGetToken() throws Exception {
        TokenRequest tokenRequest = Mockito.mock(TokenRequest.class);
        Mockito.when(apiClient.token(AUTHORIZATION_CODE, REDIRECT_URI)).thenReturn(tokenRequest);
        Mockito.when(tokenRequest.setCodeVerifier(CODE_VERIFIER)).thenReturn(tokenRequest);
        pkce.getToken(AUTHORIZATION_CODE, callback);
        Mockito.verify(apiClient).token(AUTHORIZATION_CODE, REDIRECT_URI);
        Mockito.verify(tokenRequest).setCodeVerifier(CODE_VERIFIER);
        ArgumentCaptor<BaseCallback> callbackCaptor = ArgumentCaptor.forClass(BaseCallback.class);
        Mockito.verify(tokenRequest).start(callbackCaptor.capture());
        callbackCaptor.getValue().onFailure(new AuthenticationException("Some error"));
        Mockito.verify(callback).onFailure(any(AuthenticationException.class));
    }
}