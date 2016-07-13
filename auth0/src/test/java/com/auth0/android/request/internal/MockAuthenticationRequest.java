package com.auth0.android.request.internal;

import com.auth0.android.result.Credentials;
import com.google.gson.Gson;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

public class MockAuthenticationRequest extends BaseAuthenticationRequest {

    HttpUrl url;
    OkHttpClient client;
    Gson gson;
    String method;

    public MockAuthenticationRequest(HttpUrl url, OkHttpClient client, Gson gson, String method) {
        super(url, client, gson, method, Credentials.class);
        this.url = url;
        this.client = client;
        this.gson = gson;
        this.method = method;
    }
}
