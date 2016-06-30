
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

package com.auth0.android.auth0;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.auth0.android.auth0.lib.Auth0;
import com.auth0.android.auth0.lib.authentication.AuthenticationAPIClient;
import com.auth0.android.auth0.lib.authentication.result.Credentials;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Implementation of {@link BaseProvider} that handles auth with OAuth2 web flow
 * using an external browser, sending {@link android.content.Intent#ACTION_VIEW} intent, or with {@link WebViewActivity}.
 * This behaviour is changed using {@link #useBrowser(boolean)}, and defaults to send {@link android.content.Intent#ACTION_VIEW} intent.
 */
public class WebAuthProvider {

    private static final String TAG = WebAuthProvider.class.getName();

    private static final int OAUTH2_REQUEST_CODE = 500;
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
        this.useBrowser = true;
        this.useFullscreen = false;
        this.useCodeGrant = true;
        this.parameters = new HashMap<>();
        this.connectionName = DEFAULT_CONNECTION_NAME;
    }

    public static class Builder {

        private final Auth0 account;
        private boolean useBrowser;
        private boolean useFullscreen;
        private String state;
        private String scope;
        private boolean useCodeGrant;
        private HashMap<String, Object> parameters;
        private String connectionName;

        Builder(Auth0 account) {
            this.account = account;
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
        public Builder withParameters(@Nullable HashMap<String, Object> parameters) {
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
         * Make sure to override your activity's onActivityResult method,
         * and call this provider's authorize method with the received parameters.
         *
         * @param activity context to run the authentication
         * @param callback to receive the parsed results
         */
        public void start(@NonNull Activity activity, @NonNull AuthCallback callback) {
            providerInstance = new WebAuthProvider(account)
                    .useBrowser(useBrowser)
                    .useFullscreen(useFullscreen)
                    .withState(state)
                    .withScope(scope)
                    .useCodeGrant(useCodeGrant)
                    .withParameters(parameters)
                    .withConnection(connectionName);

            providerInstance.start(activity, callback);
        }
    }

    //Begin Configuration

    private WebAuthProvider useBrowser(boolean useBrowser) {
        this.useBrowser = useBrowser;
        return this;
    }

    private WebAuthProvider useFullscreen(boolean useFullscreen) {
        this.useFullscreen = useFullscreen;
        return this;
    }

    private WebAuthProvider withState(@NonNull String state) {
        this.state = state;
        return this;
    }

    private WebAuthProvider withScope(@NonNull String scope) {
        this.scope = scope;
        return this;
    }

    private WebAuthProvider useCodeGrant(boolean useCodeGrant) {
        this.useCodeGrant = useCodeGrant;
        return this;
    }

    private WebAuthProvider withParameters(@Nullable HashMap<String, Object> parameters) {
        this.parameters = parameters != null ? new HashMap<>(parameters) : new HashMap<String, Object>();
        return this;
    }

    private WebAuthProvider withConnection(@NonNull String connectionName) {
        this.connectionName = connectionName;
        return this;
    }

    //End Configuration

    // Public methods

    public static Builder init(@NonNull Auth0 account) {
        return new Builder(account);
    }

    public static boolean resume(@NonNull AuthorizeResult data) {
        if (providerInstance == null) {
            Log.w(TAG, "There is no previous instance of this provider.");
            return false;
        }
        return providerInstance.authorize(data);
    }

    // End Public methods


    private void start(@NonNull Activity activity, @NonNull AuthCallback callback) {
        this.callback = callback;
        this.client = useCodeGrant && PKCE.isAvailable() ? account.newAuthenticationAPIClient() : null;
        requestAuth(activity);
    }

    private boolean authorize(@NonNull AuthorizeResult data) {
        if (!data.isValid(OAUTH2_REQUEST_CODE)) {
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

    private void requestAuth(Activity activity) {
        String pkgName = activity.getApplicationContext().getPackageName();
        helper = new CallbackHelper(pkgName);

        if (account.getAuthorizeUrl() == null) {
            callback.onFailure(R.string.com_auth0_lock_social_error_title, R.string.com_auth0_lock_social_invalid_authorize_url, null);
            return;
        }

        startAuthorization(activity, buildAuthorizeUri());
    }

    private void startAuthorization(Activity activity, Uri authorizeUri) {
        final Intent intent;
        if (this.useBrowser) {
            Log.d(TAG, "About to start the authorization using the Browser");
            intent = new Intent(Intent.ACTION_VIEW, authorizeUri);
            intent.addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
            activity.startActivity(intent);
        } else {
            Log.d(TAG, "About to start the authorization using the WebView");
            intent = new Intent(activity, WebViewActivity.class);
            intent.setData(authorizeUri);
            intent.putExtra(WebViewActivity.CONNECTION_NAME_EXTRA, connectionName);
            intent.putExtra(WebViewActivity.FULLSCREEN_EXTRA, useFullscreen);
            //Improvement: let LockActivity set requestCode
            activity.startActivityForResult(intent, OAUTH2_REQUEST_CODE);
        }
    }

    private boolean shouldUsePKCE() {
        return client != null;
    }

    private Uri buildAuthorizeUri() {
        final Uri authorizeUri = Uri.parse(account.getAuthorizeUrl());
        String redirectUri = helper.getCallbackURI(account.getDomainUrl());

        final Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put(KEY_SCOPE, scope != null ? scope : SCOPE_TYPE_OPENID);
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

        if (state == null) {
            state = UUID.randomUUID().toString();
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
}