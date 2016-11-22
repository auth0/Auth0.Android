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
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.authentication.ResponseType;
import com.auth0.android.jwt.Claim;
import com.auth0.android.jwt.DecodeException;
import com.auth0.android.jwt.JWT;
import com.auth0.android.result.Credentials;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth2 Web Authentication Provider.
 * It can use an external browser by sending the {@link android.content.Intent#ACTION_VIEW} intent or also the {@link WebAuthActivity}.
 * This behaviour is changed using {@link WebAuthProvider#useBrowser()}, and defaults to use browser.
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
    private static final String KEY_CONNECTION = "connection";
    private static final String KEY_CLIENT_ID = "client_id";
    private static final String KEY_REDIRECT_URI = "redirect_uri";
    private static final String KEY_SCOPE = "scope";
    private static final String KEY_CONNECTION_SCOPE = "connection_scope";
    private static final String KEY_TELEMETRY = "auth0Client";

    private static final String ERROR_VALUE_ACCESS_DENIED = "access_denied";
    private static final String SCOPE_TYPE_OPENID = "openid";
    private static final String KEY_CODE = "code";
    private static final String KEY_CODE_CHALLENGE = "code_challenge";
    private static final String KEY_CODE_CHALLENGE_METHOD = "code_challenge_method";
    private static final String METHOD_SHA_256 = "S256";

    private CallbackHelper helper;
    private final Auth0 account;
    private AuthCallback callback;
    private int requestCode;
    private PKCE pkce;

    private boolean useFullscreen;
    private boolean useBrowser;
    private Map<String, String> parameters;

    private static WebAuthProvider providerInstance;

    @VisibleForTesting
    WebAuthProvider(@NonNull Auth0 account) {
        this.account = account;
    }

    public static class Builder {

        private final Auth0 account;
        private final Map<String, String> values;
        private boolean useBrowser;
        private boolean useFullscreen;
        private PKCE pkce;

        Builder(Auth0 account) {
            this.account = account;
            this.values = new HashMap<>();

            //Default values
            this.useBrowser = true;
            this.useFullscreen = false;
            withResponseType(ResponseType.CODE);
            withState(UUID.randomUUID().toString());
            withNonce(UUID.randomUUID().toString());
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
         * Use a custom nonce in the requests
         *
         * @param nonce to use in the requests
         * @return the current builder instance
         */
        public Builder withNonce(@NonNull String nonce) {
            this.values.put(KEY_NONCE, nonce);
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
         */
        public Builder useCodeGrant(boolean useCodeGrant) {
            withResponseType(useCodeGrant ? ResponseType.CODE : ResponseType.TOKEN);
            return this;
        }

        /**
         * Choose the grant type for this request.
         *
         * @param type the ResponseType to request to the Authentication API.
         * @return the current builder instance
         */
        public Builder withResponseType(@ResponseType String type) {
            this.values.put(KEY_RESPONSE_TYPE, type);
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
            WebAuthProvider webAuth = new WebAuthProvider(account);
            webAuth.useBrowser = useBrowser;
            webAuth.useFullscreen = useFullscreen;
            webAuth.parameters = values;
            webAuth.pkce = pkce;

            providerInstance = webAuth;

            webAuth.requestAuth(activity, callback, requestCode);
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
     * @deprecated This method has been deprecated since it only applied to WebView authentication and Google is no longer supporting it. Please use {@link WebAuthProvider#requestAuth(Activity, AuthCallback, int)}
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

        final Map<String, String> values = helper.getValuesFromUri(data.getIntent().getData());
        if (values.isEmpty()) {
            Log.w(TAG, "The response didn't contain any of these values: code, state, id_token, access_token, token_type, refresh_token");
            return false;
        }

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
        } else if (values.containsKey(KEY_STATE) && !values.get(KEY_STATE).equals(getState())) {
            Log.e(TAG, String.format("Received state doesn't match. Received %s but expected %s", values.get(KEY_STATE), getState()));
            final AuthenticationException ex = new AuthenticationException("access_denied", "The received state is invalid. Try again.");
            callback.onFailure(ex);
        } else if (ResponseType.ID_TOKEN.equals(getResponseType()) && !hasValidNonce(getNonce(), values.get(KEY_ID_TOKEN))) {
            Log.e(TAG, "Received nonce doesn't match.");
            final AuthenticationException ex = new AuthenticationException("access_denied", "The received nonce is invalid. Try again.");
            callback.onFailure(ex);
        } else {
            Log.d(TAG, "Authenticated using web flow");
            if (shouldUsePKCE()) {
                pkce.getToken(values.get(KEY_CODE), callback);
            } else {
                callback.onSuccess(new Credentials(values.get(KEY_ID_TOKEN), values.get(KEY_ACCESS_TOKEN), values.get(KEY_TOKEN_TYPE), values.get(KEY_REFRESH_TOKEN)));
            }
        }
        providerInstance = null;
        return true;
    }

    private void requestAuth(@NonNull Activity activity, @NonNull AuthCallback callback, int requestCode) {
        this.callback = callback;
        this.requestCode = requestCode;
        String pkgName = activity.getApplicationContext().getPackageName();
        helper = new CallbackHelper(pkgName);

        if (account.getAuthorizeUrl() == null) {
            final AuthenticationException ex = new AuthenticationException("a0.invalid_authorize_url", "Auth0 authorize URL not properly set. This can be related to an invalid domain.");
            callback.onFailure(ex);
            providerInstance = null;
            return;
        }

        startAuthorization(activity, buildAuthorizeUri(), requestCode);
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
            intent.putExtra(WebAuthActivity.CONNECTION_NAME_EXTRA, getConnection());
            intent.putExtra(WebAuthActivity.FULLSCREEN_EXTRA, useFullscreen);
            activity.startActivityForResult(intent, requestCode);
        }
    }

    @VisibleForTesting
    static boolean hasValidNonce(String nonce, String token) {
        try {
            final JWT idToken = new JWT(token);
            final Claim nonceClaim = idToken.getClaim(KEY_NONCE);
            return !(nonceClaim == null || !nonce.equals(nonceClaim.asString()));
        } catch (DecodeException e) {
            return false;
        }
    }

    @VisibleForTesting
    boolean shouldUsePKCE() {
        return ResponseType.CODE.equals(getResponseType()) && PKCE.isAvailable();
    }

    private Uri buildAuthorizeUri() {
        final Uri authorizeUri = Uri.parse(account.getAuthorizeUrl());
        String redirectUri = helper.getCallbackURI(account.getDomainUrl());
        final Map<String, String> queryParameters = new HashMap<>(parameters);

        if (!getResponseType().equals(ResponseType.ID_TOKEN)) {
            queryParameters.remove(KEY_NONCE);
        }
        if (shouldUsePKCE()) {
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

        if (account.getTelemetry() != null) {
            queryParameters.put(KEY_TELEMETRY, account.getTelemetry().getValue());
        }
        queryParameters.put(KEY_CLIENT_ID, account.getClientId());
        queryParameters.put(KEY_REDIRECT_URI, redirectUri);

        final Uri.Builder builder = authorizeUri.buildUpon();
        for (Map.Entry<String, String> entry : queryParameters.entrySet()) {
            builder.appendQueryParameter(entry.getKey(), entry.getValue());
        }
        Uri uri = builder.build();
        Log.d(TAG, "The final Authorize Uri is " + uri.toString());
        return uri;
    }

    private PKCE createPKCE(String redirectUri) {
        return pkce == null ? new PKCE(new AuthenticationAPIClient(account), redirectUri) : pkce;
    }

    @VisibleForTesting
    static WebAuthProvider getInstance() {
        return providerInstance;
    }

    boolean useBrowser() {
        return useBrowser;
    }

    boolean useFullscreen() {
        return useFullscreen;
    }

    String getState() {
        return parameters.get(KEY_STATE);
    }

    String getNonce() {
        return parameters.get(KEY_NONCE);
    }

    String getScope() {
        return this.parameters.get(KEY_SCOPE);
    }

    String getConnectionScope() {
        return parameters.get(KEY_CONNECTION_SCOPE);
    }

    String getResponseType() {
        return parameters.get(KEY_RESPONSE_TYPE);
    }

    boolean useCodeGrant() {
        return ResponseType.CODE.equals(parameters.get(KEY_RESPONSE_TYPE));
    }

    Map<String, String> getParameters() {
        return parameters;
    }

    String getConnection() {
        return parameters.get(KEY_CONNECTION);
    }
}