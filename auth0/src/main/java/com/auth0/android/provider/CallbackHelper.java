package com.auth0.android.provider;

import android.net.Uri;
import android.util.Log;
import android.webkit.URLUtil;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

abstract class CallbackHelper {

    private static final String TAG = CallbackHelper.class.getSimpleName();

    /**
     * Generates the callback Uri for the given domain.
     *
     * @return the callback Uri.
     */
    @Nullable
    static String getCallbackUri(@NonNull String scheme, @NonNull String packageName, @NonNull String domain) {
        if (!URLUtil.isValidUrl(domain)) {
            Log.e(TAG, "The Domain is invalid and the Callback URI will not be set. You used: " + domain);
            return null;
        }

        Uri uri = Uri.parse(domain)
                .buildUpon()
                .scheme(scheme)
                .appendPath("android")
                .appendPath(packageName)
                .appendPath("callback")
                .build();

        Log.v(TAG, "The Callback URI is: " + uri);
        return uri.toString();
    }

    @NonNull
    static Map<String, String> getValuesFromUri(@Nullable Uri uri) {
        if (uri == null) {
            return Collections.emptyMap();
        }
        return asMap(uri.getQuery() != null ? uri.getQuery() : uri.getFragment());
    }

    private static Map<String, String> asMap(@Nullable String valueString) {
        if (valueString == null) {
            return new HashMap<>();
        }
        final String[] entries = valueString.length() > 0 ? valueString.split("&") : new String[]{};
        Map<String, String> values = new HashMap<>(entries.length);
        for (String entry : entries) {
            final String[] value = entry.split("=");
            if (value.length == 2) {
                values.put(value[0], value[1]);
            }
        }
        return values;
    }
}