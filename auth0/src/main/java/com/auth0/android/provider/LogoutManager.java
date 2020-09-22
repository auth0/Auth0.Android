package com.auth0.android.provider;

import android.content.Context;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("WeakerAccess")
class LogoutManager extends ResumableManager {

    private static final String TAG = LogoutManager.class.getSimpleName();

    private static final String KEY_CLIENT_ID = "client_id";
    private static final String KEY_TELEMETRY = "auth0Client";
    private static final String KEY_RETURN_TO_URL = "returnTo";

    private final Auth0 account;
    private final VoidCallback callback;
    private final Map<String, String> parameters;

    private CustomTabsOptions ctOptions;

    LogoutManager(@NonNull Auth0 account, @NonNull VoidCallback callback, @NonNull String returnToUrl, @NonNull CustomTabsOptions ctOptions) {
        this.account = account;
        this.callback = callback;
        this.parameters = new HashMap<>();
        this.parameters.put(KEY_RETURN_TO_URL, returnToUrl);
        this.ctOptions = ctOptions;
    }

    void setCustomTabsOptions(@NonNull CustomTabsOptions options) {
        this.ctOptions = options;
    }

    void startLogout(Context context) {
        addClientParameters(parameters);
        Uri uri = buildLogoutUri();

        AuthenticationActivity.authenticateUsingBrowser(context, uri, ctOptions);
    }

    @Override
    boolean resume(AuthorizeResult result) {
        if (result.isCanceled()) {
            Auth0Exception exception = new Auth0Exception("The user closed the browser app so the logout was cancelled.");
            callback.onFailure(exception);
        } else {
            callback.onSuccess(null);
        }
        return true;
    }

    private Uri buildLogoutUri() {
        Uri logoutUri = Uri.parse(account.getLogoutUrl());
        Uri.Builder builder = logoutUri.buildUpon();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            builder.appendQueryParameter(entry.getKey(), entry.getValue());
        }
        Uri uri = builder.build();
        logDebug("Using the following Logout URI: " + uri.toString());
        return uri;
    }

    private void addClientParameters(Map<String, String> parameters) {
        if (account.getTelemetry() != null) {
            parameters.put(KEY_TELEMETRY, account.getTelemetry().getValue());
        }
        parameters.put(KEY_CLIENT_ID, account.getClientId());
    }

    @VisibleForTesting
    CustomTabsOptions customTabsOptions() {
        return ctOptions;
    }

    private void logDebug(String message) {
        if (account.isLoggingEnabled()) {
            Log.d(TAG, message);
        }
    }
}
