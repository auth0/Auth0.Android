package com.auth0.android.util

import android.os.Build
import android.text.TextUtils
import android.util.Base64
import androidx.annotation.VisibleForTesting
import com.auth0.android.auth0.BuildConfig
import com.google.gson.Gson
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * Responsible for building the custom user agent header data sent on requests to Auth0.
 */
public class Auth0UserAgent public constructor(
    name: String = BuildConfig.LIBRARY_NAME,
    version: String = BuildConfig.VERSION_NAME,
    libraryVersion: String?
) {
    public constructor() : this(BuildConfig.LIBRARY_NAME, BuildConfig.VERSION_NAME)
    public constructor(
        name: String = BuildConfig.LIBRARY_NAME,
        version: String = BuildConfig.VERSION_NAME
    ) : this(name, version, null)

    public val name: String = if (TextUtils.isEmpty(name)) BuildConfig.LIBRARY_NAME else name
    public val version: String =
        if (TextUtils.isEmpty(version)) BuildConfig.VERSION_NAME else version
    public val libraryVersion: String?
        get() = environment[LIBRARY_VERSION_KEY]

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    public val environment: Map<String, String?>
    public val value: String


    public companion object {
        public const val HEADER_NAME: String = "Auth0-Client"
        private const val NAME_KEY = "name"
        private const val VERSION_KEY = "version"
        private const val ENV_KEY = "env"
        private const val LIBRARY_VERSION_KEY = "auth0.android"
        private const val ANDROID_KEY = "android"
    }

    init {
        val tmpEnv: MutableMap<String, String?> = HashMap()
        tmpEnv[ANDROID_KEY] = Build.VERSION.SDK_INT.toString()
        if (!TextUtils.isEmpty(libraryVersion)) {
            tmpEnv[LIBRARY_VERSION_KEY] = libraryVersion
        }
        environment = Collections.unmodifiableMap(tmpEnv)
        val values: MutableMap<String, Any> = HashMap()
        values[NAME_KEY] = name
        values[VERSION_KEY] = version
        values[ENV_KEY] = environment
        val json = Gson().toJson(values)
        val bytes = json.toByteArray(StandardCharsets.UTF_8)
        value = String(
            Base64.encode(bytes, Base64.URL_SAFE or Base64.NO_WRAP),
            StandardCharsets.UTF_8
        )
    }
}