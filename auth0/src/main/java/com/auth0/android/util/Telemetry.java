package com.auth0.android.util;

import android.support.annotation.VisibleForTesting;
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
    private static final String CORE_KEY = "core";
    private static final String ANDROID_KEY = "android";

    private final String name;
    private final String version;
    private final Map<String, String> env;
    private final String value;

    public Telemetry(String name, String version) {
        this(name, version, null);
    }

    public Telemetry(String name, String version, String core) {
        this.name = name;
        this.version = version;
        Map<String, String> tmpEnv = new HashMap<>();
        tmpEnv.put(ANDROID_KEY, String.valueOf(android.os.Build.VERSION.SDK_INT));
        if (core != null) {
            tmpEnv.put(CORE_KEY, core);
        }
        this.env = Collections.unmodifiableMap(tmpEnv);

        Map<String, Object> values = new HashMap<>();
        if (name != null) {
            values.put(NAME_KEY, name);
        }
        if (version != null) {
            values.put(VERSION_KEY, version);
        }
        values.put(ENV_KEY, env);
        String json = new Gson().toJson(values);
        Charset utf8 = Charset.forName("UTF-8");
        byte[] bytes = json.getBytes(utf8);
        value = new String(Base64.encode(bytes, Base64.URL_SAFE | Base64.NO_WRAP), utf8);
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
        return value;
    }
}
