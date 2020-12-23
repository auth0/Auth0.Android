/*
 * UsersAPIClientTest.java
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
import android.content.res.Resources;

import com.auth0.android.Auth0;
import com.auth0.android.request.HttpMethod;
import com.auth0.android.request.NetworkingClient;
import com.auth0.android.request.Request;
import com.auth0.android.request.RequestOptions;
import com.auth0.android.request.ServerResponse;
import com.auth0.android.request.internal.RequestFactory;
import com.auth0.android.request.internal.ThreadSwitcherShadow;
import com.auth0.android.result.UserIdentity;
import com.auth0.android.result.UserProfile;
import com.auth0.android.util.MockManagementCallback;
import com.auth0.android.util.Telemetry;
import com.auth0.android.util.TypeTokenMatcher;
import com.auth0.android.util.UsersAPI;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.mockwebserver.RecordedRequest;

import org.apache.tools.ant.filters.StringInputStream;
import org.hamcrest.collection.IsMapContaining;
import org.hamcrest.collection.IsMapWithSize;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.auth0.android.util.ManagementCallbackMatcher.hasPayloadOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isA;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(shadows = ThreadSwitcherShadow.class)
public class UsersAPIClientTest {

    private static final String CLIENT_ID = "CLIENTID";
    private static final String DOMAIN = "samples.auth0.com";
    private static final String USER_ID_PRIMARY = "primaryUserId";
    private static final String USER_ID_SECONDARY = "secondaryUserId";
    private static final String TOKEN_PRIMARY = "primaryToken";
    private static final String TOKEN_SECONDARY = "secondaryToken";
    private static final String PROVIDER = "provider";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";
    private static final String METHOD_POST = "POST";
    private static final String METHOD_DELETE = "DELETE";
    private static final String METHOD_PATCH = "PATCH";
    private static final String METHOD_GET = "GET";
    private static final String KEY_LINK_WITH = "link_with";
    private static final String KEY_USER_METADATA = "user_metadata";

    private UsersAPIClient client;
    private Gson gson;

    private UsersAPI mockAPI;

    @Before
    public void setUp() throws Exception {
        mockAPI = new UsersAPI();
        final String domain = mockAPI.getDomain();
        Auth0 auth0 = new Auth0(CLIENT_ID, domain, domain);
        client = new UsersAPIClient(auth0, TOKEN_PRIMARY);
        gson = new GsonBuilder().serializeNulls().create();
    }

    @After
    public void tearDown() throws Exception {
        mockAPI.shutdown();
    }

    @Test
    public void shouldUseCustomNetworkingClient() throws IOException {
        Auth0 account = new Auth0("client-id", "https://tenant.auth0.com/");
        InputStream inputStream = new StringInputStream("{\"id\":\"undercover\"}");
        ServerResponse response = new ServerResponse(200, inputStream, Collections.emptyMap());
        NetworkingClient networkingClient = mock(NetworkingClient.class);
        when(networkingClient.load(anyString(), any(RequestOptions.class))).thenReturn(response);
        UsersAPIClient client = new UsersAPIClient(account, "token.token", networkingClient);

        Request<UserProfile, ManagementException> request = client.getProfile("undercover");
        request.execute();

        ArgumentCaptor<RequestOptions> optionsCaptor = ArgumentCaptor.forClass(RequestOptions.class);
        verify(networkingClient).load(eq("https://tenant.auth0.com/api/v2/users/undercover"), optionsCaptor.capture());
        assertThat(optionsCaptor.getValue(), is(notNullValue()));
        assertThat(optionsCaptor.getValue().getMethod(), is(instanceOf(HttpMethod.GET.class)));
        assertThat(optionsCaptor.getValue().getParameters(), IsMapWithSize.anEmptyMap());
        assertThat(optionsCaptor.getValue().getHeaders(), is(IsMapContaining.hasKey("Auth0-Client")));
    }

    @Test
    public void shouldSetUserAgent() {
        Auth0 account = mock(Auth0.class);
        //noinspection unchecked
        RequestFactory<ManagementException> factory = mock(RequestFactory.class);
        final UsersAPIClient client = new UsersAPIClient(account, factory, gson);
        client.setUserAgent("android-user-agent");
        verify(factory).setUserAgent("android-user-agent");
    }

    @Test
    public void shouldSetTelemetryIfPresent() {
        final Telemetry telemetry = mock(Telemetry.class);
        when(telemetry.getValue()).thenReturn("the-telemetry-data");
        //noinspection unchecked
        RequestFactory<ManagementException> factory = mock(RequestFactory.class);
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setTelemetry(telemetry);
        new UsersAPIClient(auth0, factory, gson);
        verify(factory).setClientInfo("the-telemetry-data");
    }

    @Test
    public void shouldNotSetTelemetryIfMissing() {
        //noinspection unchecked
        RequestFactory<ManagementException> factory = mock(RequestFactory.class);
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.doNotSendTelemetry();
        new UsersAPIClient(auth0, factory, gson);
        verify(factory, never()).setClientInfo(any(String.class));
    }

    @Test
    public void shouldCreateClientWithAccountInfo() {
        UsersAPIClient client = new UsersAPIClient(new Auth0(CLIENT_ID, DOMAIN), TOKEN_PRIMARY);
        assertThat(client, is(notNullValue()));
        assertThat(client.getClientId(), equalTo(CLIENT_ID));
        assertThat(client.getBaseURL(), equalTo("https://" + DOMAIN + "/"));
    }

    @Test
    public void shouldCreateClientWithContextInfo() {
        Context context = mock(Context.class);
        Resources resources = mock(Resources.class);
        when(context.getPackageName()).thenReturn("com.myapp");
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq("com.myapp"))).thenReturn(222);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq("com.myapp"))).thenReturn(333);

        when(context.getString(eq(222))).thenReturn(CLIENT_ID);
        when(context.getString(eq(333))).thenReturn(DOMAIN);

        UsersAPIClient client = new UsersAPIClient(context, TOKEN_PRIMARY);

        assertThat(client, is(notNullValue()));
        assertThat(client.getClientId(), is(CLIENT_ID));
        assertThat(client.getBaseURL(), equalTo("https://" + DOMAIN + "/"));
    }

    @Test
    public void shouldLinkAccount() throws Exception {
        mockAPI.willReturnSuccessfulLink();

        final MockManagementCallback<List<UserIdentity>> callback = new MockManagementCallback<>();
        client.link(USER_ID_PRIMARY, TOKEN_SECONDARY)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY + "/identities"));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_POST));
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry(KEY_LINK_WITH, TOKEN_SECONDARY));


        TypeToken<List<UserIdentity>> typeToken = new TypeToken<List<UserIdentity>>() {
        };
        assertThat(callback, hasPayloadOfType(typeToken));
        assertThat(callback.getPayload().size(), is(2));
    }

    @Test
    public void shouldLinkAccountSync() throws Exception {
        mockAPI.willReturnSuccessfulLink();

        final List<UserIdentity> result = client.link(USER_ID_PRIMARY, TOKEN_SECONDARY)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY + "/identities"));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_POST));
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry(KEY_LINK_WITH, TOKEN_SECONDARY));


        TypeToken<List<UserIdentity>> typeToken = new TypeToken<List<UserIdentity>>() {
        };
        assertThat(result, TypeTokenMatcher.isA(typeToken));
        assertThat(result.size(), is(2));
    }

    @Test
    public void shouldUnlinkAccount() throws Exception {
        mockAPI.willReturnSuccessfulUnlink();

        final MockManagementCallback<List<UserIdentity>> callback = new MockManagementCallback<>();
        client.unlink(USER_ID_PRIMARY, USER_ID_SECONDARY, PROVIDER)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY + "/identities/" + PROVIDER + "/" + USER_ID_SECONDARY));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_DELETE));
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, is(nullValue()));


        TypeToken<List<UserIdentity>> typeToken = new TypeToken<List<UserIdentity>>() {
        };
        assertThat(callback, hasPayloadOfType(typeToken));
        assertThat(callback.getPayload().size(), is(1));
    }

    @Test
    public void shouldUnlinkAccountSync() throws Exception {
        mockAPI.willReturnSuccessfulUnlink();

        final List<UserIdentity> result = client.unlink(USER_ID_PRIMARY, USER_ID_SECONDARY, PROVIDER)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY + "/identities/" + PROVIDER + "/" + USER_ID_SECONDARY));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_DELETE));
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, is(nullValue()));


        TypeToken<List<UserIdentity>> typeToken = new TypeToken<List<UserIdentity>>() {
        };
        assertThat(result, TypeTokenMatcher.isA(typeToken));
        assertThat(result.size(), is(1));
    }

    @Test
    @Ignore("PATCH method not supported by HttpUrlConnection")
    public void shouldUpdateUserMetadata() throws Exception {
        mockAPI.willReturnUserProfile();

        final Map<String, Object> metadata = new HashMap<>();
        metadata.put("boolValue", true);
        metadata.put("name", "my_name");
        metadata.put("list", Arrays.asList("my", "name", "is"));

        final MockManagementCallback<UserProfile> callback = new MockManagementCallback<>();
        client.updateMetadata(USER_ID_PRIMARY, metadata)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_PATCH));
        Map<String, Object> body = bodyFromRequest(request);

        assertThat(body, hasKey(KEY_USER_METADATA));
        assertThat(((Map<String, Object>) body.get(KEY_USER_METADATA)), is(equalTo(metadata)));

        assertThat(callback, hasPayloadOfType(UserProfile.class));
    }

    @Test
    @Ignore("PATCH method not supported by HttpUrlConnection")
    public void shouldUpdateUserMetadataSync() throws Exception {
        mockAPI.willReturnUserProfile();

        final Map<String, Object> metadata = new HashMap<>();
        metadata.put("boolValue", true);
        metadata.put("name", "my_name");
        metadata.put("list", Arrays.asList("my", "name", "is"));

        final UserProfile result = client.updateMetadata(USER_ID_PRIMARY, metadata)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_PATCH));
        Map<String, Object> body = bodyFromRequest(request);

        assertThat(body, hasKey(KEY_USER_METADATA));
        assertThat(((Map<String, Object>) body.get(KEY_USER_METADATA)), is(equalTo(metadata)));

        assertThat(result, isA(UserProfile.class));
    }


    @Test
    public void shouldGetUserProfile() throws Exception {
        mockAPI.willReturnUserProfile();

        final MockManagementCallback<UserProfile> callback = new MockManagementCallback<>();
        client.getProfile(USER_ID_PRIMARY)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_GET));

        assertThat(callback, hasPayloadOfType(UserProfile.class));
    }

    @Test
    public void shouldGetUserProfileSync() throws Exception {
        mockAPI.willReturnUserProfile();

        final UserProfile result = client.getProfile(USER_ID_PRIMARY)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/api/v2/users/" + USER_ID_PRIMARY));

        assertThat(request.getHeader(HEADER_AUTHORIZATION), equalTo(BEARER + TOKEN_PRIMARY));
        assertThat(request.getMethod(), equalTo(METHOD_GET));

        assertThat(result, isA(UserProfile.class));
    }

    private <T> Map<String, T> bodyFromRequest(RecordedRequest request) {
        final Type mapType = new TypeToken<Map<String, T>>() {
        }.getType();
        return gson.fromJson(request.getBody().readUtf8(), mapType);
    }
}