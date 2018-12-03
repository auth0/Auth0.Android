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
import com.auth0.android.request.ErrorBuilder;
import com.google.gson.Gson;
import com.squareup.okhttp.Callback;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

import java.io.IOException;

class VoidRequest<U extends Auth0Exception> extends BaseRequest<Void, U> implements Callback {

    private final String httpMethod;

    public VoidRequest(HttpUrl url, OkHttpClient client, Gson gson, String httpMethod, ErrorBuilder<U> errorBuilder) {
        super(url, client, gson, gson.getAdapter(Void.class), errorBuilder);
        this.httpMethod = httpMethod;
    }

    @Override
    public void onResponse(Response response) {
        if (!response.isSuccessful()) {
            postOnFailure(parseUnsuccessfulResponse(response));
            return;
        }

        postOnSuccess(null);
    }

    @Override
    protected Request doBuildRequest() {
        RequestBody body = buildBody();
        return newBuilder()
                .method(httpMethod, body)
                .build();
    }

    @Override
    public Void execute() throws Auth0Exception {
        Request request = doBuildRequest();

        Response response;
        try {
            response = client.newCall(request).execute();
        } catch (IOException e) {
            throw new Auth0Exception("Failed to execute request to " + url.toString(), e);
        }

        if (!response.isSuccessful()) {
            throw parseUnsuccessfulResponse(response);
        }
        return null;
    }
}
