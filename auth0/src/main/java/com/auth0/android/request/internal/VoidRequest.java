/*
 * VoidRequest.java
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

package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.request.ErrorAdapter;
import com.auth0.android.request.HttpMethod;
import com.auth0.android.request.JsonAdapter;
import com.auth0.android.request.NetworkingClient;

//TODO: Check if un-used and remove
class VoidRequest<U extends Auth0Exception> extends BaseRequest<Void, U> {

    public VoidRequest(HttpMethod method, String url, NetworkingClient client, ErrorAdapter<U> errorAdapter) {
        super(method, url, client, createVoidResultAdapter(), errorAdapter);
    }

    private static JsonAdapter<Void> createVoidResultAdapter() {
        return json -> null;
    }
}
