/*
 * Request.java
 *
 * Copyright (c) 2015 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.auth0.android.request

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback

/**
 * Defines a request that can be started
 *
 * @param <T> the type this request will return on success.
 * @param <U> the [Auth0Exception] type this request will return on failure.
</U></T> */
public interface Request<T, U : Auth0Exception> {
    /**
     * Performs an async HTTP request against Auth0 API
     *
     * @param callback called either on success or failure
     */
    public fun start(callback: Callback<T, U>)

    /**
     * Executes the HTTP request against Auth0 API (blocking the current thread)
     *
     * @return the response on success
     * @throws Auth0Exception on failure
     */
    @Throws(Auth0Exception::class)
    public fun execute(): T?

    /**
     * Add parameters to the request as a Map of Object with the keys as String
     *
     * @param parameters to send with the request
     * @return itself
     */
    public fun addParameters(parameters: Map<String, String>): Request<T, U>

    /**
     * Add parameter to the request with a given name
     *
     * @param name  of the parameter
     * @param value of the parameter
     * @return itself
     */
    public fun addParameter(name: String, value: String): Request<T, U>

    /**
     * Adds an additional header for the request
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     */
    public fun addHeader(name: String, value: String): Request<T, U>
}