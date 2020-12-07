package com.auth0.android.request.kt

/**
 * Holder for the information required to configure a request
 */
public class RequestOptions(internal val method: HttpMethod) {
    internal val parameters: MutableMap<String, String> = mutableMapOf()
    internal val headers: MutableMap<String, String> = mutableMapOf()
}