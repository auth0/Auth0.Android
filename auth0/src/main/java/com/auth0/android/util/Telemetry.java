package com.auth0.android.util;

import android.support.annotation.VisibleForTesting;

import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

public class Telemetry {
    public static final String HEADER_NAME = "Auth0-Client";

    private static final String NAME_KEY = "name";
    private static final String VERSION_KEY = "version";
    private static final String ENV_KEY = "env";
    private static final String CORE_KEY = "core";
    private static final String ANDROID_KEY = "android";

    private final String name;
    private final String version;
    private final Map<String, String> env;

    public Telemetry(String name, String version) {
        this(name, version, null);
    }

    public Telemetry(String name, String version, String core) {
        this.name = name;
        this.version = version;
        this.env = new HashMap<>();
        env.put(ANDROID_KEY, String.valueOf(android.os.Build.VERSION.SDK_INT));
        if (core != null) {
            env.put(CORE_KEY, core);
        }
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public String getLibraryVersion() {
        return env.get(CORE_KEY);
    }

    @VisibleForTesting
    Map<String, String> getEnvironment() {
        return env;
    }

    public String getValue() {
        Map<String, Object> values = new HashMap<>();
        if (name != null) {
            values.put(NAME_KEY, name);
        }
        if (version != null) {
            values.put(VERSION_KEY, version);
        }
        values.put(ENV_KEY, env);
        String json = new Gson().toJson(values);
        return Base64.encodeUrlSafe(json);
    }
}
