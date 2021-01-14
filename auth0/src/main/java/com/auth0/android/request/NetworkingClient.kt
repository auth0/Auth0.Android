package com.auth0.android.request

import java.io.IOException

/**
 * Client used internally by this library to execute network requests.
 * This is the main extensibility point for customizing the Networking Stack.
 */
public interface NetworkingClient {

    /**
     * Builds a network request to the given URL using the provided options, and returns the result
     * wrapped in a ServerResponse object.
     * @param url the destination URL to make the request to.
     * @param options the additional options required to construct the request.
     * @return a ServerResponse object wrapping the received result.
     * @throws IOException if anything happened while constructing or executing the request.
     */
    @Throws(IOException::class)
    public fun load(url: String, options: RequestOptions): ServerResponse
}