package com.auth0.android.request.kt

public sealed class HttpMethod {

    public object GET : HttpMethod()
    public object POST : HttpMethod()

}