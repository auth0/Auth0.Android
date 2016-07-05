/*
 * AuthenticationAPIClient.java
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

package com.auth0.android.auth0.lib.management;

import com.auth0.android.Auth0;
import com.auth0.android.auth0.lib.result.UserIdentity;
import com.auth0.android.authentication.ParameterBuilder;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.Request;
import com.auth0.android.request.internal.RequestFactory;
import com.auth0.android.util.Telemetry;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.util.List;
import java.util.Map;

/**
 * API client for Auth0 Management API.
 * <p/>
 * <pre><code>
 * Auth0 auth0 = new Auth0("your_client_id", "your_domain");
 * UsersAPIClient client = new UsersAPIClient(auth0);
 * </code></pre>
 *
 * @see <a href="https://auth0.com/docs/api/management/v2">Auth API docs</a>
 */
public class UsersAPIClient {

    private static final String LINK_WITH_KEY = "link_with";
    private static final String API_PATH = "api";
    private static final String V2_PATH = "v2";
    private static final String USERS_PATH = "users";
    private static final String IDENTITIES_PATH = "identities";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    private final Auth0 auth0;
    private final OkHttpClient client;
    private final Gson gson;
    private final RequestFactory factory;
    private final ErrorBuilder<ManagementException> mgmtErrorBuilder;

    /**
     * Creates a new API client instance providing Auth0 account info.
     *
     * @param auth0 account information
     */
    public UsersAPIClient(Auth0 auth0) {
        this(auth0, new OkHttpClient(), GsonProvider.buildGson());
    }

    private UsersAPIClient(Auth0 auth0, OkHttpClient client, Gson gson) {
        this.auth0 = auth0;
        this.client = client;
        this.gson = gson;
        this.factory = new RequestFactory();
        this.mgmtErrorBuilder = new ManagementErrorBuilder();
        final Telemetry telemetry = auth0.getTelemetry();
        if (telemetry != null) {
            factory.setClientInfo(telemetry.getValue());
        }
    }

    public String getClientId() {
        return auth0.getClientId();
    }

    public String getBaseURL() {
        return auth0.getDomainUrl();
    }

    /**
     * Set the value of 'User-Agent' header for every request to Auth0 Authentication API
     *
     * @param userAgent value to send in every request to Auth0
     */
    @SuppressWarnings("unused")
    public void setUserAgent(String userAgent) {
        factory.setUserAgent(userAgent);
    }


    /**
     * Link a user identity calling <a href="https://auth0.com/docs/link-accounts#the-api">'/api/v2/users/:primaryUserId/identities'</a> endpoint
     * Example usage:
     * <pre><code>
     * client.link("{auth0 primary user id}", "{user primary id token}", "{user secondary id token}")
     *      .start(new BaseCallback<List<UserIdentity>>() {
     *          {@literal}Override
     *          public void onSuccess(List<UserIdentity> payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(ManagementException error) {}
     *      });
     * </code></pre>
     *
     * @param primaryUserId    of the identity to link
     * @param primaryIdToken   of the main identity obtained after login
     * @param secondaryIdToken of the secondary identity obtained after login
     * @return a request to start
     */
    @SuppressWarnings("WeakerAccess")
    public Request<List<UserIdentity>, ManagementException> link(String primaryUserId, String primaryIdToken, String secondaryIdToken) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(API_PATH)
                .addPathSegment(V2_PATH)
                .addPathSegment(USERS_PATH)
                .addPathSegment(primaryUserId)
                .addPathSegment(IDENTITIES_PATH)
                .build();

        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .set(LINK_WITH_KEY, secondaryIdToken)
                .asDictionary();

        TypeToken<List<UserIdentity>> typeToken = new TypeToken<List<UserIdentity>>() {
        };
        return factory.POST(url, client, gson, typeToken, mgmtErrorBuilder)
                .addHeader(AUTHORIZATION_HEADER, "Bearer " + primaryIdToken)
                .addParameters(parameters);
    }

    /**
     * Unlink a user identity calling <a href="https://auth0.com/docs/link-accounts#unlinking-accounts">'/api/v2/users/:primaryIdToken/identities/secondaryProvider/secondaryUserId'</a> endpoint
     * Example usage:
     * <pre><code>
     * client.unlink("{auth0 primary user id}", "{user primary id token}", {auth0 secondary user id}, "{secondary provider}")
     *      .start(new BaseCallback<List<UserIdentity>>() {
     *          {@literal}Override
     *          public void onSuccess(List<UserIdentity> payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(ManagementException error) {}
     *      });
     * </code></pre>
     *
     * @param primaryUserId     of the primary identity to unlink
     * @param primaryIdToken    of the main identity obtained after login
     * @param secondaryUserId   of the secondary identity you wish to unlink from the main one.
     * @param secondaryProvider of the secondary identity you wish to unlink from the main one.
     * @return a request to start
     */
    @SuppressWarnings("WeakerAccess")
    public Request<List<UserIdentity>, ManagementException> unlink(String primaryUserId, String primaryIdToken, String secondaryUserId, String secondaryProvider) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(API_PATH)
                .addPathSegment(V2_PATH)
                .addPathSegment(USERS_PATH)
                .addPathSegment(primaryUserId)
                .addPathSegment(IDENTITIES_PATH)
                .addPathSegment(secondaryProvider)
                .addPathSegment(secondaryUserId)
                .build();

        TypeToken<List<UserIdentity>> typeToken = new TypeToken<List<UserIdentity>>() {
        };
        return factory.DELETE(url, client, gson, typeToken, mgmtErrorBuilder)
                .addHeader(AUTHORIZATION_HEADER, "Bearer " + primaryIdToken);
    }

}
