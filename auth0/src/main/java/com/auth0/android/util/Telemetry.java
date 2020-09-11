package com.auth0.android.util;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.text.TextUtils;
import android.util.Base64;

import com.google.gson.Gson;

import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


public class Telemetry {
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

    public Telemetry(@NonNull String name, @NonNull String version) {
        this(name, version, null);
    }

    public Telemetry(@NonNull String name, @NonNull String version, @Nullable String libraryVersion) {
        this.name = name;
        this.version = version;
        if (TextUtils.isEmpty(name)) {
            env = Collections.emptyMap();
            value = null;
            return;
        }
        Map<String, String> tmpEnv = new HashMap<>();
        tmpEnv.put(ANDROID_KEY, String.valueOf(android.os.Build.VERSION.SDK_INT));
        if (!TextUtils.isEmpty(libraryVersion)) {
            //noinspection ConstantConditions
            tmpEnv.put(LIBRARY_VERSION_KEY, libraryVersion);
        }
        this.env = Collections.unmodifiableMap(tmpEnv);

        Map<String, Object> values = new HashMap<>();
        values.put(NAME_KEY, name);
        if (!TextUtils.isEmpty(version)) {
            values.put(VERSION_KEY, version);
        }
        values.put(ENV_KEY, env);
        String json = new Gson().toJson(values);
        Charset utf8 = Charset.forName("UTF-8");
        byte[] bytes = json.getBytes(utf8);
        value = new String(Base64.encode(bytes, Base64.URL_SAFE | Base64.NO_WRAP), utf8);
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
