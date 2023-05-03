package com.auth0.android.request.internal

import androidx.annotation.VisibleForTesting
import java.util.*

/**
 * Small utility class to handle OpenID Connect conformance
 */
internal object OidcUtils {
    internal const val KEY_SCOPE = "scope"
    internal const val DEFAULT_SCOPE = "openid profile email"
    internal const val REQUIRED_SCOPE = "openid"

    /**
     * Given a string, it will check if it contains the scope of "openid".
     * If it does, it will keep it unchanged. Otherwise, it will append "openid".
     *
     * @param scope the scope to check if includes "openid"
     * @return a scope that contains "openid"
     */
    fun includeRequiredScope(scope: String): String {
        val existingScopes = scope.split(" ")
            .map { it.toLowerCase(Locale.ROOT) }
        return if (!existingScopes.contains(REQUIRED_SCOPE)) {
            (existingScopes + REQUIRED_SCOPE).joinToString(separator = " ").trim()
        } else {
            scope
        }
    }

    /**
     * Given a map, it will check if it contains a key with the name "scope" in it.
     * If the "scope" key is not defined, it will add one with the value of "openid profile email".
     * If the "scope" key is defined and its value contains "openid", it will keep it unchanged.
     * Otherwise, it will append "openid" to it.
     *
     * @param parameters the map to check if includes a scope of "openid""
     * @return a map with a scope containing "openid" or "openid profile email".
     */
    fun includeDefaultScope(parameters: MutableMap<String, String>) {
        parameters[KEY_SCOPE] = if (parameters.containsKey(KEY_SCOPE)) {
            includeRequiredScope(parameters.getValue(KEY_SCOPE))
        } else {
            DEFAULT_SCOPE
        }
    }
}