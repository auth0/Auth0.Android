package com.auth0.android.request

import java.io.IOException

public interface NetworkingClient {

    @Throws(IOException::class)
    public fun load(url: String, options: RequestOptions): ServerResponse
}