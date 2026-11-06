package com.auth0.android.provider;

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import com.auth0.android.NetworkErrorException;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.Callback;
import com.auth0.android.request.Request;
import com.auth0.android.result.Credentials;

import java.net.ConnectException;
import java.net.UnknownHostException;
import java.util.Map;

/**
 * Performs code exchange according to Proof Key for Code Exchange (PKCE) spec.
 */
class PKCE {
    static final String TAG = PKCE.class.getSimpleName();
    static final int DEFAULT_MAX_NETWORK_RETRIES = 3;
    static final long DEFAULT_NETWORK_RETRY_DELAY_MS = 1000;

    final AuthenticationAPIClient apiClient;
    private final String codeVerifier;
    private final String redirectUri;
    private final String codeChallenge;
    private final Map<String, String> headers;
    private int maxNetworkRetries = DEFAULT_MAX_NETWORK_RETRIES;
    private long networkRetryDelayMillis = DEFAULT_NETWORK_RETRY_DELAY_MS;

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

    PKCE(@NonNull AuthenticationAPIClient apiClient,
                @NonNull String codeVerifier,
                @NonNull String redirectUri,
                @NonNull String codeChallenge,
                @NonNull Map<String, String> headers) {
        this.apiClient = apiClient;
        this.codeVerifier = codeVerifier;
        this.redirectUri = redirectUri;
        this.codeChallenge = codeChallenge;
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

    public String getCodeVerifier() {
        return codeVerifier;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    void setNetworkRetry(int maxRetries, long delayMillis) {
        this.maxNetworkRetries = maxRetries;
        this.networkRetryDelayMillis = delayMillis;
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
        tokenRequest.start(new Callback<Credentials, AuthenticationException>() {
            private int retries = 0;

            @Override
            public void onSuccess(@NonNull Credentials result) {
                callback.onSuccess(result);
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
                // Android 15+ blocks network for cached apps and lifts it asynchronously when the
                // redirect brings the app back, so the exchange can race it. Only failures before
                // the request was sent are retried, as the authorization code is single-use.
                if (retries < maxNetworkRetries && isUnsentRequestError(error)) {
                    retries++;
                    Callback<Credentials, AuthenticationException> retry = this;
                    new Handler(Looper.getMainLooper()).postDelayed(() -> tokenRequest.start(retry), networkRetryDelayMillis);
                    return;
                }
                callback.onFailure(error);
            }
        });
    }

    private static boolean isUnsentRequestError(AuthenticationException error) {
        Throwable cause = error.getCause();
        if (!(cause instanceof NetworkErrorException)) {
            return false;
        }
        Throwable networkCause = cause.getCause();
        return networkCause instanceof UnknownHostException || networkCause instanceof ConnectException;
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
