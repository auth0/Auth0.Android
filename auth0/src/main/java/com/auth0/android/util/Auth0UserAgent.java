package com.auth0.android.util;

import android.text.TextUtils;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import com.auth0.android.auth0.BuildConfig;
import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Responsible for building the custom user agent header data sent on requests to Auth0.
 */
public class Auth0UserAgent {
    public static final String HEADER_NAME = "Auth0-Client";

    private static final String NAME_KEY = "name";
    private static final String VERSION_KEY = "version";
    private static final String ENV_KEY = "env";
    private static final String LIBRARY_VERSION_KEY = "auth0.android";
    private static final String ANDROID_KEY = "android";

    private final String name;
    private final String version;
    private final Map<String, String> env;
    private final String value;

    public Auth0UserAgent() {
        this(BuildConfig.LIBRARY_NAME, BuildConfig.VERSION_NAME);
    }

    public Auth0UserAgent(@NonNull String name, @NonNull String version) {
        this(name, version, null);
    }

    public Auth0UserAgent(@NonNull String name, @NonNull String version, @Nullable String libraryVersion) {
        this.name = TextUtils.isEmpty(name) ? BuildConfig.LIBRARY_NAME : name;
        this.version = TextUtils.isEmpty(version) ? BuildConfig.VERSION_NAME : version;

        Map<String, String> tmpEnv = new HashMap<>();
        tmpEnv.put(ANDROID_KEY, String.valueOf(android.os.Build.VERSION.SDK_INT));
        if (!TextUtils.isEmpty(libraryVersion)) {
            tmpEnv.put(LIBRARY_VERSION_KEY, libraryVersion);
        }
        this.env = Collections.unmodifiableMap(tmpEnv);

        Map<String, Object> values = new HashMap<>();
        values.put(NAME_KEY, name);
        values.put(VERSION_KEY, version);
        values.put(ENV_KEY, env);
        String json = new Gson().toJson(values);
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        value = new String(Base64.encode(bytes, Base64.URL_SAFE | Base64.NO_WRAP),
                StandardCharsets.UTF_8);
    }

    @NonNull
    public String getName() {
        return name;
    }

    @NonNull
    public String getVersion() {
        return version;
    }

    @Nullable
    public String getLibraryVersion() {
        return env.get(LIBRARY_VERSION_KEY);
    }

    @VisibleForTesting
    Map<String, String> getEnvironment() {
        return env;
    }

    @NonNull
    public String getValue() {
        return value;
    }
}
