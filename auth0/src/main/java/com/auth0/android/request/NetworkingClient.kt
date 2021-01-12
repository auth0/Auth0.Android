package com.auth0.android.request

import java.io.IOException

public interface NetworkingClient {

    /**
     * Creates and executes a networking request.
     * The result is wrapped into a ServerResponse before being returned.
     */
    @Throws(IOException::class)
    public fun load(url: String, options: RequestOptions): ServerResponse
}