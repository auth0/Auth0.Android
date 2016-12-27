/*
 * WebAuthProvider.java
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

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.util.Base64;
import android.util.Log;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.jwt.Claim;
import com.auth0.android.jwt.DecodeException;
import com.auth0.android.jwt.JWT;
import com.auth0.android.result.Credentials;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * OAuth2 Web Authentication Provider.
 * It can use an external browser by sending the {@link android.content.Intent#ACTION_VIEW} intent or also the {@link WebAuthActivity}.
 * This behaviour is changed using {@link WebAuthProvider.Builder#useBrowser(boolean)}, and defaults to use browser.
 */
public class WebAuthProvider {

    private static final String TAG = WebAuthProvider.class.getName();

    private static final String KEY_ERROR = "error";
    private static final String KEY_ID_TOKEN = "id_token";
    private static final String KEY_ACCESS_TOKEN = "access_token";
    private static final String KEY_TOKEN_TYPE = "token_type";
    private static final String KEY_REFRESH_TOKEN = "refresh_token";
    private static final String KEY_RESPONSE_TYPE = "response_type";
    private static final String KEY_STATE = "state";
    private static final String KEY_NONCE = "nonce";
    private static final String KEY_AUDIENCE = "audience";
    private static final String KEY_CONNECTION = "connection";
    private static final String KEY_CLIENT_ID = "client_id";
    private static final String KEY_REDIRECT_URI = "redirect_uri";
    private static final String KEY_SCOPE = "scope";
    private static final String KEY_CONNECTION_SCOPE = "connection_scope";
    private static final String KEY_TELEMETRY = "auth0Client";

    private static final String ERROR_VALUE_ACCESS_DENIED = "access_denied";
    private static final String SCOPE_TYPE_OPENID = "openid";
    private static final String RESPONSE_TYPE_ID_TOKEN = "id_token";
    private static final String RESPONSE_TYPE_TOKEN = "token";
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String KEY_CODE = "code";
    private static final String KEY_CODE_CHALLENGE = "code_challenge";
    private static final String KEY_CODE_CHALLENGE_METHOD = "code_challenge_method";
    private static final String METHOD_SHA_256 = "S256";

    private int requestCode;
    private AuthCallback callback;
    private PKCE pkce;

    private boolean useFullscreen;
    private boolean useBrowser;

    private static WebAuthProvider providerInstance;
    private Map<String, String> sentValues;


    public static class Builder {

        private final Auth0 account;
        private final Map<String, String> values;
        private boolean useBrowser;
        private boolean useFullscreen;
        private PKCE pkce;
        private String scheme;

        Builder(Auth0 account) {
            this.account = account;
            this.values = new HashMap<>();

            //Default values
            this.scheme = "https";
            this.useBrowser = true;
            this.useFullscreen = false;
            withResponseType(ResponseType.CODE);
            withScope(SCOPE_TYPE_OPENID);
        }

        /**
         * If the class authenticates with an external browser or not.
         *
         * @param useBrowser if the authentication is handled in a Browser.
         * @return the current builder instance
         * @deprecated This method has been deprecated since it only applied to WebView authentication and Google is no longer supporting it. You should use the default value (use browser).
         */
        @Deprecated
        public Builder useBrowser(boolean useBrowser) {
            this.useBrowser = useBrowser;
            return this;
        }

        /**
         * If the activity should be fullscreen or not. Applies only to the WebView activity, not to the
         * Browser authentication.
         *
         * @param useFullscreen if the activity should be fullscreen or not.
         * @return the current builder instance
         * @deprecated This method has been deprecated since it only applied to WebView authentication and Google is no longer supporting it.
         */
        @Deprecated
        public Builder useFullscreen(boolean useFullscreen) {
            this.useFullscreen = useFullscreen;
            return this;
        }

        /**
         * Use a custom state in the requests
         *
         * @param state to use in the requests
         * @return the current builder instance
         */
        public Builder withState(@NonNull String state) {
            this.values.put(KEY_STATE, state);
            return this;
        }

        /**
         * Specify a custom nonce value to avoid replay attacks. It will be sent in the auth request that will be returned back as a claim in the id_token
         *
         * @param nonce to use in the requests
         * @return the current builder instance
         */
        public Builder withNonce(@NonNull String nonce) {
            this.values.put(KEY_NONCE, nonce);
            return this;
        }

        /**
         * Use a custom audience in the requests
         *
         * @param audience to use in the requests
         * @return the current builder instance
         */
        public Builder withAudience(@NonNull String audience) {
            this.values.put(KEY_AUDIENCE, audience);
            return this;
        }

        /**
         * Specify a custom Scheme to use on the Callback Uri. Default scheme is 'https'.
         *
         * @param scheme to use in the Callback Uri.
         * @return the current builder instance
         */
        public Builder withScheme(@NonNull String scheme) {
            String lowerCase = scheme.toLowerCase();
            if (!scheme.equals(lowerCase)) {
                Log.w(TAG, "Please provide the scheme in lowercase and make sure it's the same configured in the intent filter. Android expects the scheme in lowercase");
            }
            this.scheme = scheme;
            return this;
        }

        /**
         * Give a scope for this request.
         *
         * @param scope to request.
         * @return the current builder instance
         */
        public Builder withScope(@NonNull String scope) {
            this.values.put(KEY_SCOPE, scope);
            return this;
        }

        /**
         * Give a connection scope for this request.
         *
         * @param connectionScope to request.
         * @return the current builder instance
         */
        public Builder withConnectionScope(@NonNull String... connectionScope) {
            StringBuilder sb = new StringBuilder();
            for (String s : connectionScope) {
                sb.append(s.trim()).append(" ");
            }
            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1);
                this.values.put(KEY_CONNECTION_SCOPE, sb.toString());
            }
            return this;
        }

        /**
         * Choose the grant type for this request.
         *
         * @param useCodeGrant whether use code or implicit grant type
         * @return the current builder instance
         * @deprecated Please use {@link WebAuthProvider.Builder#withResponseType(int)} to specify a custom Response Type
         */
        @Deprecated
        public Builder useCodeGrant(boolean useCodeGrant) {
            withResponseType(useCodeGrant ? ResponseType.CODE : ResponseType.TOKEN);
            return this;
        }

        /**
         * Choose the grant type for this request.
         *
         * @param type the ResponseType to request to the Authentication API. Multiple ResponseType's can be defined using a pipe. "CODE | TOKEN"
         * @return the current builder instance
         */
        public Builder withResponseType(@ResponseType int type) {
            StringBuilder sb = new StringBuilder();
            if (FlagChecker.hasFlag(type, ResponseType.CODE)) {
                sb.append(RESPONSE_TYPE_CODE).append(" ");
            }
            if (FlagChecker.hasFlag(type, ResponseType.ID_TOKEN)) {
                sb.append(RESPONSE_TYPE_ID_TOKEN).append(" ");
            }
            if (FlagChecker.hasFlag(type, ResponseType.TOKEN)) {
                sb.append(RESPONSE_TYPE_TOKEN);
            }
            this.values.put(KEY_RESPONSE_TYPE, sb.toString().trim());
            return this;
        }

        /**
         * Use extra parameters on the request.
         *
         * @param parameters to add
         * @return the current builder instance
         */
        public Builder withParameters(@NonNull Map<String, Object> parameters) {
            for (Map.Entry<String, Object> entry : parameters.entrySet()) {
                if (entry.getValue() != null) {
                    this.values.put(entry.getKey(), entry.getValue().toString());
                }
            }
            return this;
        }

        /**
         * Use the given connection. By default no connection is specified, so the hosted login page will be displayed.
         *
         * @param connectionName to use
         * @return the current builder instance
         */
        public Builder withConnection(@NonNull String connectionName) {
            this.values.put(KEY_CONNECTION, connectionName);
            return this;
        }

        @VisibleForTesting
        Builder withPKCE(PKCE pkce) {
            this.pkce = pkce;
            return this;
        }

        /**
         * Begins the authentication flow.
         * Make sure to override your activity's onNewIntent() and onActivityResult() methods,
         * and call this provider's resume() method with the received parameters.
         *
         * @param activity    context to run the authentication
         * @param callback    to receive the parsed results
         * @param requestCode to use in the authentication request
         * @deprecated This method has been deprecated since it only applied to WebView authentication and Google is no longer supporting it. Please use {@link WebAuthProvider.Builder#start(Activity, AuthCallback)}
         */
        @Deprecated
        public void start(@NonNull Activity activity, @NonNull AuthCallback callback, int requestCode) {
            WebAuthProvider webAuth = new WebAuthProvider();
            webAuth.useBrowser = useBrowser;
            webAuth.useFullscreen = useFullscreen;
            webAuth.pkce = pkce;

            providerInstance = webAuth;

            String pkgName = activity.getApplicationContext().getPackageName();
            String redirectUri = CallbackHelper.getCallbackURI(scheme, pkgName, account.getDomainUrl());
            Uri uri = buildAuthorizeUri(redirectUri);

            webAuth.sentValues = whiteListSentValues(values);
            webAuth.startAuthorization(activity, uri, requestCode);
        }

        private Map<String, String> whiteListSentValues(Map<String, String> values) {
            Map<String, String> sentValues = new HashMap<>();
            sentValues.put(KEY_CONNECTION, values.get(KEY_CONNECTION));
            sentValues.put(KEY_NONCE, values.get(KEY_NONCE));
            sentValues.put(KEY_STATE, values.get(KEY_STATE));
            sentValues.put(KEY_RESPONSE_TYPE, values.get(KEY_RESPONSE_TYPE));
            return sentValues;
        }

        /**
         * Begins the authentication flow.
         * Make sure to override your activity's onNewIntent() method and call this provider's resume() method with the received parameters.
         *
         * @param activity context to run the authentication
         * @param callback to receive the parsed results
         */
        public void start(@NonNull Activity activity, @NonNull AuthCallback callback) {
            this.start(activity, callback, 110);
        }

        @VisibleForTesting
        Uri buildAuthorizeUri(String redirectUri) {
            final Uri authorizeUri = Uri.parse(account.getAuthorizeUrl());
            final Map<String, String> queryParameters = new HashMap<>(values);

            if (shouldUsePKCE(values.get(KEY_RESPONSE_TYPE))) {
                try {
                    pkce = createPKCE(redirectUri);
                    String codeChallenge = pkce.getCodeChallenge();
                    queryParameters.put(KEY_CODE_CHALLENGE, codeChallenge);
                    queryParameters.put(KEY_CODE_CHALLENGE_METHOD, METHOD_SHA_256);
                    Log.v(TAG, "Using PKCE authentication flow");
                } catch (IllegalStateException e) {
                    Log.e(TAG, "Some algorithms aren't available on this device and PKCE can't be used. Defaulting to token response_type.", e);
                }
            }

            if (values.get(KEY_RESPONSE_TYPE).contains(RESPONSE_TYPE_ID_TOKEN)) {
                final String nonce = getRandomString(values.get(KEY_NONCE));
                values.put(KEY_NONCE, nonce);
                queryParameters.put(KEY_NONCE, nonce);
            }
            if (account.getTelemetry() != null) {
                queryParameters.put(KEY_TELEMETRY, account.getTelemetry().getValue());
            }

            final String state = getRandomString(values.get(KEY_STATE));
            values.put(KEY_STATE, state);
            queryParameters.put(KEY_STATE, state);
            queryParameters.put(KEY_CLIENT_ID, account.getClientId());
            queryParameters.put(KEY_REDIRECT_URI, redirectUri);

            final Uri.Builder builder = authorizeUri.buildUpon();
            for (Map.Entry<String, String> entry : queryParameters.entrySet()) {
                builder.appendQueryParameter(entry.getKey(), entry.getValue());
            }
            Uri uri = builder.build();
//            logDebug("Using the following AuthorizeURI: " + uri.toString());
            return uri;
        }

        @VisibleForTesting
        static String getRandomString(@Nullable String defaultValue) {
            return defaultValue != null ? defaultValue : secureRandomString();
        }

        private static String secureRandomString() {
            final SecureRandom sr = new SecureRandom();
            final byte[] randomBytes = new byte[32];
            sr.nextBytes(randomBytes);
            return Base64.encodeToString(randomBytes, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        }

        private PKCE createPKCE(String redirectUri) {
            if (pkce != null) {
                return pkce;
            }
            final AuthenticationAPIClient client = new AuthenticationAPIClient(account);
            return new PKCE(client, redirectUri);
        }
    }

    // Public methods

    /**
     * Initialize the WebAuthProvider instance with an account. Additional settings can be configured
     * in the Builder, like setting the connection name or authentication parameters.
     *
     * @param account to use for authentication
     * @return a new Builder instance to customize.
     */
    public static Builder init(@NonNull Auth0 account) {
        return new Builder(account);
    }


    /**
     * Initialize the WebAuthProvider instance with an Android Context. Additional settings can be configured
     * in the Builder, like setting the connection name or authentication parameters.
     *
     * @param context a valid context.
     * @return a new Builder instance to customize.
     */
    public static Builder init(@NonNull Context context) {
        return new Builder(new Auth0(context));
    }

    /**
     * Finishes the authentication flow by passing the data received in the activity's onActivityResult() callback.
     * The final authentication result will be delivered to the callback specified when calling start().
     *
     * @param requestCode the request code received on the onActivityResult() call
     * @param resultCode  the result code received on the onActivityResult() call
     * @param intent      the data received on the onActivityResult() call
     * @return true if a result was expected and has a valid format, or false if not.
     * @deprecated This method has been deprecated since it only applied to WebView authentication and Google is no longer supporting it. Please use {@link WebAuthProvider#resume(Intent)}
     */
    @Deprecated
    public static boolean resume(int requestCode, int resultCode, @Nullable Intent intent) {
        if (providerInstance == null) {
            Log.w(TAG, "There is no previous instance of this provider.");
            return false;
        }
        final AuthorizeResult data = new AuthorizeResult(requestCode, resultCode, intent);
        return providerInstance.authorize(data);
    }

    /**
     * Finishes the authentication flow by passing the data received in the activity's onNewIntent() callback.
     * The final authentication result will be delivered to the callback specified when calling start().
     *
     * @param intent the data received on the onNewIntent() call
     * @return true if a result was expected and has a valid format, or false if not.
     */
    public static boolean resume(@Nullable Intent intent) {
        if (providerInstance == null) {
            Log.w(TAG, "There is no previous instance of this provider.");
            return false;
        }
        final AuthorizeResult data = new AuthorizeResult(intent);
        return providerInstance.authorize(data);
    }

    // End Public methods

    private boolean authorize(@NonNull AuthorizeResult data) {
        if (!data.isValid(requestCode)) {
            Log.w(TAG, "The Authorize Result is invalid.");
            return false;
        }

        final Map<String, String> values = CallbackHelper.getValuesFromUri(data.getIntent().getData());
        if (values.isEmpty()) {
            Log.w(TAG, "The response didn't contain any of these values: code, state, id_token, access_token, token_type, refresh_token");
            return false;
        }
//        logDebug("The parsed CallbackURI contains the following values: " + values);

        if (values.containsKey(KEY_ERROR)) {
            Log.e(TAG, "Error, access denied. Check that the required Permissions are granted and that the Application has this Connection configured in Auth0 Dashboard.");
            final AuthenticationException ex;
            if (ERROR_VALUE_ACCESS_DENIED.equalsIgnoreCase(values.get(KEY_ERROR))) {
                //noinspection ThrowableInstanceNeverThrown
                ex = new AuthenticationException("access_denied", "Permissions were not granted. Try again.");
            } else {
                //noinspection ThrowableInstanceNeverThrown
                ex = new AuthenticationException("a0.invalid_configuration", "The application isn't configured properly for the social connection. Please check your Auth0's application configuration");
            }
            callback.onFailure(ex);
        } else if (values.containsKey(KEY_STATE) && !values.get(KEY_STATE).equals(sentValues.get(KEY_STATE))) {
            Log.e(TAG, String.format("Received state doesn't match. Received %s but expected %s", values.get(KEY_STATE), sentValues.get(KEY_STATE)));
            final AuthenticationException ex = new AuthenticationException("access_denied", "The received state is invalid. Try again.");
            callback.onFailure(ex);
        } else if (sentValues.get(KEY_RESPONSE_TYPE).contains(RESPONSE_TYPE_ID_TOKEN) && !hasValidNonce(sentValues.get(KEY_NONCE), values.get(KEY_ID_TOKEN))) {
            Log.e(TAG, "Received nonce doesn't match.");
            final AuthenticationException ex = new AuthenticationException("access_denied", "The received nonce is invalid. Try again.");
            callback.onFailure(ex);
        } else {
            Log.d(TAG, "Authenticated using web flow");
            final Credentials urlCredentials = new Credentials(values.get(KEY_ID_TOKEN), values.get(KEY_ACCESS_TOKEN), values.get(KEY_TOKEN_TYPE), values.get(KEY_REFRESH_TOKEN));
            if (shouldUsePKCE(sentValues.get(KEY_RESPONSE_TYPE))) {
                pkce.getToken(values.get(KEY_CODE), new AuthCallback() {
                    @Override
                    public void onFailure(@NonNull Dialog dialog) {
                        callback.onFailure(dialog);
                    }

                    @Override
                    public void onFailure(AuthenticationException exception) {
                        callback.onFailure(exception);
                    }

                    @Override
                    public void onSuccess(@NonNull Credentials codeCredentials) {
                        callback.onSuccess(mergeCredentials(urlCredentials, codeCredentials));
                    }
                });
            } else {
                callback.onSuccess(urlCredentials);
            }
        }
        providerInstance = null;
        return true;
    }

    private void startAuthorization(Activity activity, Uri authorizeUri, int requestCode) {
        final Intent intent;
        if (this.useBrowser) {
            Log.d(TAG, "About to start the authorization using the Browser");
            intent = new Intent(Intent.ACTION_VIEW, authorizeUri);
            intent.addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
            activity.startActivity(intent);
        } else {
            Log.d(TAG, "About to start the authorization using the WebView");
            intent = new Intent(activity, WebAuthActivity.class);
            intent.setData(authorizeUri);
            intent.putExtra(WebAuthActivity.CONNECTION_NAME_EXTRA, sentValues.get(KEY_CONNECTION));
            intent.putExtra(WebAuthActivity.FULLSCREEN_EXTRA, useFullscreen);
            activity.startActivityForResult(intent, requestCode);
        }
    }

    @VisibleForTesting
    static Credentials mergeCredentials(Credentials urlCredentials, Credentials codeCredentials) {
        final String idToken = codeCredentials.getIdToken() != null ? codeCredentials.getIdToken() : urlCredentials.getIdToken();
        final String accessToken = codeCredentials.getAccessToken() != null ? codeCredentials.getAccessToken() : urlCredentials.getAccessToken();
        final String type = codeCredentials.getType() != null ? codeCredentials.getType() : urlCredentials.getType();
        final String refreshToken = codeCredentials.getRefreshToken() != null ? codeCredentials.getRefreshToken() : urlCredentials.getRefreshToken();

        return new Credentials(idToken, accessToken, type, refreshToken);
    }

    @VisibleForTesting
    static boolean hasValidNonce(@Nullable String nonce, @NonNull String token) {
        try {
            final JWT idToken = new JWT(token);
            final Claim nonceClaim = idToken.getClaim(KEY_NONCE);
            return nonce != null && nonceClaim != null && nonce.equals(nonceClaim.asString());
        } catch (DecodeException e) {
            return false;
        }
    }

    private static boolean shouldUsePKCE(String responseType) {
        return responseType.contains(RESPONSE_TYPE_CODE) && PKCE.isAvailable();
    }
}