package com.auth0.android.provider;

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
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
    private static final int DEFAULT_MAX_NETWORK_RETRIES = 2;
    // Android caches failed DNS lookups for 2 seconds, so a shorter delay retries against the cached failure.
    private static final int DEFAULT_NETWORK_RETRY_DELAY_SECONDS = 2;

    final AuthenticationAPIClient apiClient;
    private final String codeVerifier;
    private final String redirectUri;
    private final String codeChallenge;
    private final Map<String, String> headers;
    private final int maxNetworkRetries;
    private final int networkRetryDelaySeconds;
    private final Handler retryHandler = new Handler(Looper.getMainLooper());

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
        this(apiClient, redirectUri, headers, null, null);
    }

    /**
     * Same as {@link #PKCE(AuthenticationAPIClient, String, Map)}, with the code exchange retry settings.
     *
     * @param maxNetworkRetries        retries when the code exchange fails before it was sent, or null for the default.
     * @param networkRetryDelaySeconds delay between those retries, or null for the default.
     */
    PKCE(@NonNull AuthenticationAPIClient apiClient, String redirectUri, @NonNull Map<String, String> headers,
         @Nullable Integer maxNetworkRetries, @Nullable Integer networkRetryDelaySeconds) {
        this(apiClient, new AlgorithmHelper(), redirectUri, headers, maxNetworkRetries, networkRetryDelaySeconds);
    }

    @VisibleForTesting
    PKCE(@NonNull AuthenticationAPIClient apiClient, @NonNull AlgorithmHelper algorithmHelper,
         @NonNull String redirectUri, @NonNull Map<String, String> headers) {
        this(apiClient, algorithmHelper, redirectUri, headers, null, null);
    }

    @VisibleForTesting
    PKCE(@NonNull AuthenticationAPIClient apiClient, @NonNull AlgorithmHelper algorithmHelper,
         @NonNull String redirectUri, @NonNull Map<String, String> headers,
         @Nullable Integer maxNetworkRetries, @Nullable Integer networkRetryDelaySeconds) {
        this.apiClient = apiClient;
        this.redirectUri = redirectUri;
        this.codeVerifier = algorithmHelper.generateCodeVerifier();
        this.codeChallenge = algorithmHelper.generateCodeChallenge(codeVerifier);
        this.headers = headers;
        this.maxNetworkRetries = maxNetworkRetries != null ? maxNetworkRetries : DEFAULT_MAX_NETWORK_RETRIES;
        this.networkRetryDelaySeconds = networkRetryDelaySeconds != null ? networkRetryDelaySeconds : DEFAULT_NETWORK_RETRY_DELAY_SECONDS;
    }

    PKCE(@NonNull AuthenticationAPIClient apiClient,
                @NonNull String codeVerifier,
                @NonNull String redirectUri,
                @NonNull String codeChallenge,
                @NonNull Map<String, String> headers,
                @Nullable Integer maxNetworkRetries,
                @Nullable Integer networkRetryDelaySeconds) {
        this.apiClient = apiClient;
        this.codeVerifier = codeVerifier;
        this.redirectUri = redirectUri;
        this.codeChallenge = codeChallenge;
        this.headers = headers;
        this.maxNetworkRetries = maxNetworkRetries != null ? maxNetworkRetries : DEFAULT_MAX_NETWORK_RETRIES;
        this.networkRetryDelaySeconds = networkRetryDelaySeconds != null ? networkRetryDelaySeconds : DEFAULT_NETWORK_RETRY_DELAY_SECONDS;
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

    int getMaxNetworkRetries() {
        return maxNetworkRetries;
    }

    int getNetworkRetryDelaySeconds() {
        return networkRetryDelaySeconds;
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
        startTokenRequest(tokenRequest, callback, 0);
    }

    private void startTokenRequest(@NonNull Request<Credentials, AuthenticationException> tokenRequest,
                                   @NonNull Callback<Credentials, AuthenticationException> callback,
                                   int attempt) {
        tokenRequest.start(new Callback<Credentials, AuthenticationException>() {
            @Override
            public void onSuccess(@NonNull Credentials result) {
                callback.onSuccess(result);
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
                if (shouldRetry(error, attempt)) {
                    retryHandler.postDelayed(() -> startTokenRequest(tokenRequest, callback, attempt + 1),
                            networkRetryDelaySeconds * 1000L);
                } else {
                    callback.onFailure(error);
                }
            }
        });
    }

    // Android 15+ blocks network for cached apps and lifts it asynchronously when the redirect
    // brings the app back, so the exchange can race it. Only failures before the request was sent
    // are retried, as the authorization code is single-use.
    private boolean shouldRetry(@NonNull AuthenticationException error, int attempt) {
        Throwable cause = error.getCause();
        return attempt < maxNetworkRetries
                && cause instanceof NetworkErrorException
                && isUnsentRequestError(cause.getCause());
    }

    // OkHttp attaches the failures it already recovered from as suppressed exceptions, and any of
    // those that isn't a DNS or connect failure means the request may have been sent.
    private boolean isUnsentRequestError(@Nullable Throwable error) {
        if (!(error instanceof UnknownHostException || error instanceof ConnectException)) {
            return false;
        }
        for (Throwable suppressed : error.getSuppressed()) {
            if (!isUnsentRequestError(suppressed)) {
                return false;
            }
        }
        return true;
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
