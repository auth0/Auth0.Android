package com.auth0.android.request

/**
 * Holder for the information required to configure a request
 */
public class RequestOptions(public val method: HttpMethod) {
    public val parameters: MutableMap<String, Any> = mutableMapOf()
    public val headers: MutableMap<String, String> = mutableMapOf()
}