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

package com.auth0.android.management;


import android.content.Context;
import android.support.annotation.VisibleForTesting;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.ParameterBuilder;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.Request;
import com.auth0.android.request.internal.GsonProvider;
import com.auth0.android.request.internal.ManagementErrorBuilder;
import com.auth0.android.request.internal.RequestFactory;
import com.auth0.android.result.UserIdentity;
import com.auth0.android.result.UserProfile;
import com.auth0.android.request.internal.OkHttpClientFactory;
import com.auth0.android.util.Telemetry;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.util.List;
import java.util.Map;

/**
 * API client for Auth0 Management API.
 * <pre>
 * {@code
 * Auth0 auth0 = new Auth0("your_client_id", "your_domain");
 * UsersAPIClient client = new UsersAPIClient(auth0);
 * }
 * </pre>
 *
 * @see <a href="https://auth0.com/docs/api/management/v2">Auth API docs</a>
 */
public class UsersAPIClient {

    private static final String LINK_WITH_KEY = "link_with";
    private static final String API_PATH = "api";
    private static final String V2_PATH = "v2";
    private static final String USERS_PATH = "users";
    private static final String IDENTITIES_PATH = "identities";
    private static final String USER_METADATA_KEY = "user_metadata";

    private final Auth0 auth0;
    @VisibleForTesting final OkHttpClient client;
    private final Gson gson;
    private final RequestFactory factory;
    private final ErrorBuilder<ManagementException> mgmtErrorBuilder;

    /**
     * Creates a new API client instance providing Auth0 account info.
     *
     * @param auth0 account information
     * @param token of the primary identity
     */
    public UsersAPIClient(Auth0 auth0, String token) {
        this(auth0, new RequestFactory(token), new OkHttpClientFactory(), GsonProvider.buildGson());
    }

    /**
     * Creates a new API client instance using the 'com_auth0_client_id' and 'com_auth0_domain' values
     * defined in the project String resources file.
     *
     * @param context a valid Context
     * @param token   of the primary identity
     */
    public UsersAPIClient(Context context, String token) {
        this(new Auth0(context), token);
    }

    @VisibleForTesting
    UsersAPIClient(Auth0 auth0, RequestFactory factory, OkHttpClientFactory clientFactory) {
        this(auth0, factory, clientFactory, GsonProvider.buildGson());
    }

    private UsersAPIClient(Auth0 auth0, RequestFactory factory, OkHttpClientFactory clientFactory, Gson gson) {
        this.auth0 = auth0;
        client = clientFactory.createClient(auth0.isLoggingEnabled(), auth0.isTLS12Enforced());
        this.gson = gson;
        this.factory = factory;
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
     * Link a user identity calling <a href="https://auth0.com/docs/link-accounts#the-management-api">'/api/v2/users/:primaryUserId/identities'</a> endpoint
     * Example usage:
     * <pre>
     * {@code
     * client.link("{auth0 primary user id}", "{user secondary token}")
     *      .start(new BaseCallback<List<UserIdentity>, ManagementException>() {
     *          {@literal}Override
     *          public void onSuccess(List<UserIdentity> payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(ManagementException error) {}
     *      });
     * }
     * </pre>
     *
     * @param primaryUserId  of the identity to link
     * @param secondaryToken of the secondary identity obtained after login
     * @return a request to start
     */
    @SuppressWarnings("WeakerAccess")
    public Request<List<UserIdentity>, ManagementException> link(String primaryUserId, String secondaryToken) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(API_PATH)
                .addPathSegment(V2_PATH)
                .addPathSegment(USERS_PATH)
                .addPathSegment(primaryUserId)
                .addPathSegment(IDENTITIES_PATH)
                .build();

        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .set(LINK_WITH_KEY, secondaryToken)
                .asDictionary();

        TypeToken<List<UserIdentity>> typeToken = new TypeToken<List<UserIdentity>>() {
        };
        return factory.POST(url, client, gson, typeToken, mgmtErrorBuilder)
                .addParameters(parameters);
    }

    /**
     * Unlink a user identity calling <a href="https://auth0.com/docs/link-accounts#unlinking-accounts">'/api/v2/users/:primaryToken/identities/secondaryProvider/secondaryUserId'</a> endpoint
     * Example usage:
     * <pre>
     * {@code
     * client.unlink("{auth0 primary user id}", {auth0 secondary user id}, "{secondary provider}")
     *      .start(new BaseCallback<List<UserIdentity>, ManagementException>() {
     *          {@literal}Override
     *          public void onSuccess(List<UserIdentity> payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(ManagementException error) {}
     *      });
     * }
     * </pre>
     *
     * @param primaryUserId     of the primary identity to unlink
     * @param secondaryUserId   of the secondary identity you wish to unlink from the main one.
     * @param secondaryProvider of the secondary identity you wish to unlink from the main one.
     * @return a request to start
     */
    @SuppressWarnings("WeakerAccess")
    public Request<List<UserIdentity>, ManagementException> unlink(String primaryUserId, String secondaryUserId, String secondaryProvider) {
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
        return factory.DELETE(url, client, gson, typeToken, mgmtErrorBuilder);
    }

    /**
     * Update the user_metadata calling <a href="https://auth0.com/docs/api/management/v2#!/Users/patch_users_by_id">'/api/v2/users/:userId'</a> endpoint
     * Example usage:
     * <pre>
     * {@code
     * client.updateMetadata("{user id}", "{user metadata}")
     *      .start(new BaseCallback<UserProfile, ManagementException>() {
     *          {@literal}Override
     *          public void onSuccess(UserProfile payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(ManagementException error) {}
     *      });
     * }
     * </pre>
     *
     * @param userId       of the primary identity to unlink
     * @param userMetadata to merge with the existing one
     * @return a request to start
     */
    @SuppressWarnings("WeakerAccess")
    public Request<UserProfile, ManagementException> updateMetadata(String userId, Map<String, Object> userMetadata) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(API_PATH)
                .addPathSegment(V2_PATH)
                .addPathSegment(USERS_PATH)
                .addPathSegment(userId)
                .build();

        return factory.PATCH(url, client, gson, UserProfile.class, mgmtErrorBuilder)
                .addParameter(USER_METADATA_KEY, userMetadata);
    }

    /**
     * Get the User Profile calling <a href="https://auth0.com/docs/api/management/v2#!/Users/get_users_by_id">'/api/v2/users/:userId'</a> endpoint
     * Example usage:
     * <pre>
     * {@code
     * client.getProfile("{user id}")
     *      .start(new BaseCallback<UserProfile, ManagementException>() {
     *          {@literal}Override
     *          public void onSuccess(UserProfile payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(ManagementException error) {}
     *      });
     * }
     * </pre>
     *
     * @param userId identity of the user
     * @return a request to start
     */
    @SuppressWarnings("WeakerAccess")
    public Request<UserProfile, ManagementException> getProfile(String userId) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(API_PATH)
                .addPathSegment(V2_PATH)
                .addPathSegment(USERS_PATH)
                .addPathSegment(userId)
                .build();

        return factory.GET(url, client, gson, UserProfile.class, mgmtErrorBuilder);
    }

}
