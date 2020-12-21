package com.auth0.android.request.kt

public sealed class HttpMethod {

    public object GET : HttpMethod()
    public object POST : HttpMethod()
    public object PATCH : HttpMethod()
    public object DELETE : HttpMethod()

    override fun toString(): String {
        return when (this) {
            GET -> "GET"
            POST -> "POST"
            PATCH -> "PATCH"
            DELETE -> "DELETE"
        }
    }
}