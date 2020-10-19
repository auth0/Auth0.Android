/*
 * AuthorizableRequest.java
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

package com.auth0.android.request;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;

/**
 * Interface for a Auth0 request that need Authorization using a JWT.
 *
 * @param <T> the type this request will return on success.
 * @param <U> the {@link Auth0Exception} type this request will return on failure.
 */
public interface AuthorizableRequest<T, U extends Auth0Exception> extends ParameterizableRequest<T, U> {

    /**
     * Set the JWT used in 'Authorization' header value
     *
     * @param jwt token to send to the API
     * @return itself
     */
    @NonNull
    AuthorizableRequest<T, U> setBearer(@NonNull String jwt);

}
