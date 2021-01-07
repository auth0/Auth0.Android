/*
 * PKCE.java
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

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.Callback;
import com.auth0.android.request.Request;
import com.auth0.android.result.Credentials;

import java.util.Map;

/**
 * Performs code exchange according to Proof Key for Code Exchange (PKCE) spec.
 */
class PKCE {
    static final String TAG = PKCE.class.getSimpleName();

    final AuthenticationAPIClient apiClient;
    private final String codeVerifier;
    private final String redirectUri;
    private final String codeChallenge;
    private final Map<String, String> headers;

    /**
     * Creates a new instance of this class with the given AuthenticationAPIClient.
     * The instance should be disposed after a call to getToken().
     *
     * @param apiClient   to get the OAuth Token.
     * @param redirectUri going to be used in the OAuth code request.
     * @param headers     HTTP headers added to the OAuth token request.
     * @throws IllegalStateException when either 'US-ASCII` encoding or 'SHA-256' algorithm is not available.
     * @see #isAvailable()
     */
    public PKCE(@NonNull AuthenticationAPIClient apiClient, String redirectUri, @NonNull Map<String, String> headers) {
        this(apiClient, new AlgorithmHelper(), redirectUri, headers);
    }

    @VisibleForTesting
    PKCE(@NonNull AuthenticationAPIClient apiClient, @NonNull AlgorithmHelper algorithmHelper,
         @NonNull String redirectUri, @NonNull Map<String, String> headers) {
        this.apiClient = apiClient;
        this.redirectUri = redirectUri;
        this.codeVerifier = algorithmHelper.generateCodeVerifier();
        this.codeChallenge = algorithmHelper.generateCodeChallenge(codeVerifier);
        this.headers = headers;
    }

    /**
     * Returns the Code Challenge generated using a Code Verifier.
     *
     * @return the Code Challenge for this session.
     */
    public String getCodeChallenge() {
        return codeChallenge;
    }

    /**
     * Performs a request to the Auth0 API to get the OAuth Token and end the PKCE flow.
     * The instance of this class must be disposed after this method is called.
     *
     * @param authorizationCode received in the call to /authorize with a "grant_type=code"
     * @param callback          to notify the result of this call to.
     */
    public void getToken(String authorizationCode, @NonNull final Callback<Credentials, AuthenticationException> callback) {
        Request<Credentials, AuthenticationException> tokenRequest = apiClient.token(authorizationCode, codeVerifier, redirectUri);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            tokenRequest.addHeader(entry.getKey(), entry.getValue());
        }
        tokenRequest.start(callback);
    }

    /**
     * Checks if this device is capable of using the PKCE flow when performing calls to the
     * /authorize endpoint.
     *
     * @return if this device can use PKCE flow or not.
     */
    static boolean isAvailable() {
        return isAvailable(new AlgorithmHelper());
    }

    @VisibleForTesting
    static boolean isAvailable(@NonNull AlgorithmHelper algorithmHelper) {
        try {
            byte[] input = algorithmHelper.getASCIIBytes("test");
            algorithmHelper.getSHA256(input);
        } catch (Exception ignored) {
            return false;
        }
        return true;
    }
}
