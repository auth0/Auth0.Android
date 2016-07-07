
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
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.auth0.android.auth0.R;
import com.auth0.android.Auth0;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.result.Credentials;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth2 Web Authentication Provider.
 * It can use an external browser by sending the {@link android.content.Intent#ACTION_VIEW} intent, or also the {@link WebAuthActivity}.
 * This behaviour is changed using {@link WebAuthProvider#useBrowser()}, and defaults to use browser.
 */
public class WebAuthProvider {

    private static final String TAG = WebAuthProvider.class.getName();

    private static final String DEFAULT_CONNECTION_NAME = "auth0";

    private static final String KEY_ERROR = "error";
    private static final String KEY_ID_TOKEN = "id_token";
    private static final String KEY_ACCESS_TOKEN = "access_token";
    private static final String KEY_TOKEN_TYPE = "token_type";
    private static final String KEY_REFRESH_TOKEN = "refresh_token";
    private static final String KEY_RESPONSE_TYPE = "response_type";
    private static final String KEY_STATE = "state";
    private static final String KEY_CONNECTION = "connection";
    private static final String KEY_CLIENT_ID = "client_id";
    private static final String KEY_REDIRECT_URI = "redirect_uri";
    private static final String KEY_SCOPE = "scope";
    private static final String KEY_TELEMETRY = "auth0Client";

    private static final String ERROR_VALUE_ACCESS_DENIED = "access_denied";
    private static final String RESPONSE_TYPE_TOKEN = "token";
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String SCOPE_TYPE_OPENID = "openid";
    private static final String KEY_CODE = "code";
    private static final String KEY_CODE_CHALLENGE = "code_challenge";
    private static final String KEY_CODE_CHALLENGE_METHOD = "code_challenge_method";
    private static final String METHOD_SHA_256 = "S256";

    private CallbackHelper helper;
    private final Auth0 account;
    private AuthCallback callback;
    private int requestCode;
    private AuthenticationAPIClient client;
    private PKCE pkce;

    private boolean useFullscreen;
    private boolean useBrowser;
    private String state;
    private String scope;
    private boolean useCodeGrant;
    private Map<String, Object> parameters;
    private String connectionName;

    private static WebAuthProvider providerInstance;

    private WebAuthProvider(@NonNull Auth0 account) {
        this.account = account;
    }

    public static class Builder {

        private final Auth0 account;
        private boolean useBrowser;
        private boolean useFullscreen;
        private String state;
        private String scope;
        private boolean useCodeGrant;
        private Map<String, Object> parameters;
        private String connectionName;

        Builder(Auth0 account) {
            this.account = account;

            //Default values
            this.useBrowser = true;
            this.useFullscreen = false;
            this.useCodeGrant = true;
            this.parameters = new HashMap<>();
            this.state = UUID.randomUUID().toString();
            this.scope = SCOPE_TYPE_OPENID;
            this.connectionName = DEFAULT_CONNECTION_NAME;
        }

        /**
         * If the class authenticates with an external browser or not.
         *
         * @param useBrowser if the authentication is handled in a Browser.
         */
        public Builder useBrowser(boolean useBrowser) {
            this.useBrowser = useBrowser;
            return this;
        }

        /**
         * If the activity should be fullscreen or not. Applies only to the WebView activity, not to the
         * Browser authentication.
         *
         * @param useFullscreen if the activity should be fullscreen or not.
         */
        public Builder useFullscreen(boolean useFullscreen) {
            this.useFullscreen = useFullscreen;
            return this;
        }

        /**
         * Use a custom state in the requests
         *
         * @param state to use in the requests
         */
        public Builder withState(@NonNull String state) {
            this.state = state;
            return this;
        }

        /**
         * Give a scope for this request.
         *
         * @param scope to request.
         */
        public Builder withScope(@NonNull String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * Choose the grant type for this request.
         *
         * @param useCodeGrant whether use code or implicit grant type
         */
        public Builder useCodeGrant(boolean useCodeGrant) {
            this.useCodeGrant = useCodeGrant;
            return this;
        }

        /**
         * Use extra parameters on the request
         *
         * @param parameters to add
         */
        public Builder withParameters(@Nullable Map<String, Object> parameters) {
            this.parameters = parameters != null ? new HashMap<>(parameters) : new HashMap<String, Object>();
            return this;
        }

        /**
         * Use the given connection instead of the default 'auth0'.
         *
         * @param connectionName to use
         */
        public Builder withConnection(@NonNull String connectionName) {
            this.connectionName = connectionName;
            return this;
        }

        /**
         * Begins the authentication flow.
         * Make sure to override your activity's onActivityResult() method,
         * and call this provider's resume() method with the received parameters.
         *
         * @param activity    context to run the authentication
         * @param callback    to receive the parsed results
         * @param requestCode to use in the authentication request
         */
        public void start(@NonNull Activity activity, @NonNull AuthCallback callback, int requestCode) {
            WebAuthProvider webAuth = new WebAuthProvider(account);
            webAuth.useBrowser = useBrowser;
            webAuth.useFullscreen = useFullscreen;
            webAuth.state = state;
            webAuth.scope = scope;
            webAuth.useCodeGrant = useCodeGrant;
            webAuth.parameters = parameters;
            webAuth.connectionName = connectionName;

            providerInstance = webAuth;

            webAuth.requestAuth(activity, callback, requestCode);
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
     * Finishes the authentication flow by passing the data received in the activity's onActivityResult() callback.
     * The final authentication result will be delivered to the callback specified when calling start().
     *
     * @param requestCode the request code received on the onActivityResult() call
     * @param resultCode  the result code received on the onActivityResult() call
     * @param intent      the data received on the onActivityResult() call
     * @return true if a result was expected and has a valid format, or false if not.
     */
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
            final int message = ERROR_VALUE_ACCESS_DENIED.equalsIgnoreCase(values.get(KEY_ERROR)) ? R.string.com_auth0_lock_social_access_denied_message : R.string.com_auth0_lock_social_error_message;
            callback.onFailure(R.string.com_auth0_lock_social_error_title, message, null);
        } else if (values.containsKey(KEY_STATE) && !values.get(KEY_STATE).equals(state)) {
            Log.e(TAG, String.format("Received state doesn't match. Received %s but expected %s", values.get(KEY_STATE), state));
            callback.onFailure(R.string.com_auth0_lock_social_error_title, R.string.com_auth0_lock_social_invalid_state, null);
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
        this.client = useCodeGrant && PKCE.isAvailable() ? account.newAuthenticationAPIClient() : null;
        String pkgName = activity.getApplicationContext().getPackageName();
        helper = new CallbackHelper(pkgName);

        if (account.getAuthorizeUrl() == null) {
            callback.onFailure(R.string.com_auth0_lock_social_error_title, R.string.com_auth0_lock_social_invalid_authorize_url, null);
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
            intent.putExtra(WebAuthActivity.CONNECTION_NAME_EXTRA, connectionName);
            intent.putExtra(WebAuthActivity.FULLSCREEN_EXTRA, useFullscreen);
            activity.startActivityForResult(intent, requestCode);
        }
    }

    private boolean shouldUsePKCE() {
        return client != null;
    }

    private Uri buildAuthorizeUri() {
        final Uri authorizeUri = Uri.parse(account.getAuthorizeUrl());
        String redirectUri = helper.getCallbackURI(account.getDomainUrl());

        final Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put(KEY_SCOPE, scope);
        queryParameters.put(KEY_RESPONSE_TYPE, RESPONSE_TYPE_TOKEN);

        if (shouldUsePKCE()) {
            try {
                pkce = new PKCE(client, redirectUri);
                String codeChallenge = pkce.getCodeChallenge();
                queryParameters.put(KEY_RESPONSE_TYPE, RESPONSE_TYPE_CODE);
                queryParameters.put(KEY_CODE_CHALLENGE, codeChallenge);
                queryParameters.put(KEY_CODE_CHALLENGE_METHOD, METHOD_SHA_256);
                Log.v(TAG, "Using PKCE authentication flow");
            } catch (IllegalStateException e) {
                Log.e(TAG, "Some algorithms aren't available on this device and PKCE can't be used. Defaulting to token response_type.", e);
            }
        }

        Log.v(TAG, String.format("Adding %d user parameters to the Authorize Uri", parameters.size()));
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            Object value = entry.getValue();
            if (value != null) {
                queryParameters.put(entry.getKey(), value.toString());
            }
        }

        if (account.getTelemetry() != null) {
            queryParameters.put(KEY_TELEMETRY, account.getTelemetry().getValue());
        }

        queryParameters.put(KEY_STATE, state);
        queryParameters.put(KEY_CONNECTION, connectionName);
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

    //Test helper methods (package local)
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
        return state;
    }

    String getScope() {
        return scope;
    }

    boolean useCodeGrant() {
        return useCodeGrant;
    }

    Map<String, Object> getParameters() {
        return parameters;
    }

    String getConnection() {
        return connectionName;
    }
}