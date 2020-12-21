/*
 * AuthenticationAPIClientTest.java
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

package com.auth0.android.authentication;


import android.content.Context;
import android.content.res.Resources;

import com.auth0.android.Auth0;
import com.auth0.android.request.internal.RequestFactory;
import com.auth0.android.result.Authentication;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.DatabaseUser;
import com.auth0.android.result.UserProfile;
import com.auth0.android.util.AuthenticationAPI;
import com.auth0.android.util.MockAuthenticationCallback;
import com.auth0.android.util.Telemetry;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.mockwebserver.RecordedRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;

import java.lang.reflect.Type;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;

import kotlin.Unit;

import static com.auth0.android.util.AuthenticationCallbackMatcher.hasError;
import static com.auth0.android.util.AuthenticationCallbackMatcher.hasNoError;
import static com.auth0.android.util.AuthenticationCallbackMatcher.hasPayload;
import static com.auth0.android.util.AuthenticationCallbackMatcher.hasPayloadOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class AuthenticationAPIClientTest {

    private static final String CLIENT_ID = "CLIENTID";
    private static final String DOMAIN = "samples.auth0.com";
    private static final String PASSWORD = "123123123";
    private static final String SUPPORT_AUTH0_COM = "support@auth0.com";
    private static final String SUPPORT = "support";
    private static final String MY_CONNECTION = "MyConnection";
    private static final String FIRST_NAME = "John";
    private static final String LAST_NAME = "Doe";
    private static final String COMPANY = "Auth0";
    private static final String OPENID = "openid";
    private static final String DEFAULT_LOCALE_IF_MISSING = "en_US";

    private AuthenticationAPIClient client;
    private Gson gson;

    private AuthenticationAPI mockAPI;

    @Before
    public void setUp() throws Exception {
        mockAPI = new AuthenticationAPI();
        final String domain = mockAPI.getDomain();
        Auth0 auth0 = new Auth0(CLIENT_ID, domain, domain);
        client = new AuthenticationAPIClient(auth0);
        gson = new GsonBuilder().serializeNulls().create();
    }

    @After
    public void tearDown() throws Exception {
        mockAPI.shutdown();
    }

    @Test
    public void shouldSetUserAgent() {
        Auth0 account = mock(Auth0.class);
        //noinspection unchecked
        RequestFactory<AuthenticationException> factory = mock(RequestFactory.class);
        AuthenticationAPIClient client = new AuthenticationAPIClient(account, factory, gson);
        client.setUserAgent("nexus-5x");
        verify(factory).setUserAgent("nexus-5x");
    }

    @Test
    public void shouldSetTelemetryIfPresent() {
        final Telemetry telemetry = mock(Telemetry.class);
        when(telemetry.getValue()).thenReturn("the-telemetry-data");
        //noinspection unchecked
        RequestFactory<AuthenticationException> factory = mock(RequestFactory.class);
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.setTelemetry(telemetry);
        new AuthenticationAPIClient(auth0, factory, gson);
        verify(factory).setClientInfo("the-telemetry-data");
    }

    @Test
    public void shouldNotSetTelemetryIfMissing() {
        //noinspection unchecked
        RequestFactory<AuthenticationException> factory = mock(RequestFactory.class);
        Auth0 auth0 = new Auth0(CLIENT_ID, DOMAIN);
        auth0.doNotSendTelemetry();
        new AuthenticationAPIClient(auth0, factory, gson);
        verify(factory, never()).setClientInfo(anyString());
    }

    @Test
    public void shouldCreateClientWithAccountInfo() {
        AuthenticationAPIClient client = new AuthenticationAPIClient(new Auth0(CLIENT_ID, DOMAIN));
        assertThat(client, is(notNullValue()));
        assertThat(client.getClientId(), equalTo(CLIENT_ID));
        assertThat(HttpUrl.parse(client.getBaseURL()), notNullValue());
        assertThat(HttpUrl.parse(client.getBaseURL()).scheme(), equalTo("https"));
        assertThat(HttpUrl.parse(client.getBaseURL()).host(), equalTo(DOMAIN));
        assertThat(HttpUrl.parse(client.getBaseURL()).pathSize(), is(1));
        assertThat(HttpUrl.parse(client.getBaseURL()).encodedPath(), is("/"));
    }

    @Test
    public void shouldCreateClientWithContextInfo() {
        Context context = Mockito.mock(Context.class);
        Resources resources = Mockito.mock(Resources.class);
        when(context.getPackageName()).thenReturn("com.myapp");
        when(context.getResources()).thenReturn(resources);
        when(resources.getIdentifier(eq("com_auth0_client_id"), eq("string"), eq("com.myapp"))).thenReturn(222);
        when(resources.getIdentifier(eq("com_auth0_domain"), eq("string"), eq("com.myapp"))).thenReturn(333);

        when(context.getString(eq(222))).thenReturn(CLIENT_ID);
        when(context.getString(eq(333))).thenReturn(DOMAIN);

        AuthenticationAPIClient client = new AuthenticationAPIClient(context);

        assertThat(client, is(notNullValue()));
        assertThat(client.getClientId(), is(CLIENT_ID));
        assertThat(client.getBaseURL(), equalTo("https://" + DOMAIN + "/"));
    }

    @Test
    public void shouldLoginWithMFAOTPCode() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);
        client.loginWithOTP("ey30.the-mfa-token.value", "123456")
                .start(callback);
        assertThat(callback, hasPayloadOfType(Credentials.class));

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        Map<String, String> body = bodyFromRequest(request);

        assertThat(request.getPath(), equalTo("/oauth/token"));
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/mfa-otp"));
        assertThat(body, hasEntry("mfa_token", "ey30.the-mfa-token.value"));
        assertThat(body, hasEntry("otp", "123456"));
        assertThat(body, not(hasKey("username")));
        assertThat(body, not(hasKey("password")));
        assertThat(body, not(hasKey("connection")));
    }

    @Test
    public void shouldLoginWithUserAndPasswordSync() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        final Credentials credentials = client
                .login(SUPPORT_AUTH0_COM, "voidpassword", MY_CONNECTION)
                .execute();

        assertThat(credentials, is(notNullValue()));

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("realm", MY_CONNECTION));
        assertThat(body, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm"));
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
    }

    @Test
    public void shouldLoginWithPasswordRealmGrant() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);
        client.login(SUPPORT_AUTH0_COM, "some-password", MY_CONNECTION)
                .start(callback);
        assertThat(callback, hasPayloadOfType(Credentials.class));

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        Map<String, String> body = bodyFromRequest(request);

        assertThat(request.getPath(), equalTo("/oauth/token"));
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm"));
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("password", "some-password"));
        assertThat(body, hasEntry("realm", MY_CONNECTION));
        assertThat(body, not(hasKey("connection")));
        assertThat(body, not(hasKey("scope")));
        assertThat(body, not(hasKey("audience")));
    }

    @Test
    public void shouldLoginWithUserAndPasswordUsingOAuthTokenEndpoint() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();

        client.login(SUPPORT_AUTH0_COM, "some-password")
                .start(callback);
        assertThat(callback, hasPayloadOfType(Credentials.class));

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), is("/oauth/token"));
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", "password"));
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("password", "some-password"));
        assertThat(body, not(hasKey("realm")));
        assertThat(body, not(hasKey("connection")));
        assertThat(body, not(hasKey("scope")));
        assertThat(body, not(hasKey("audience")));
    }

    @Test
    public void shouldLoginWithUserAndPasswordSyncUsingOAuthTokenEndpoint() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        final Credentials credentials = client
                .login(SUPPORT_AUTH0_COM, "some-password")
                .execute();
        assertThat(credentials, is(notNullValue()));

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), is("/oauth/token"));
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", "password"));
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("password", "some-password"));
        assertThat(body, not(hasKey("realm")));
        assertThat(body, not(hasKey("connection")));
        assertThat(body, not(hasKey("scope")));
        assertThat(body, not(hasKey("audience")));
    }

    @Test
    public void shouldFetchUserInfo() throws Exception {
        mockAPI.willReturnUserInfo();
        final MockAuthenticationCallback<UserProfile> callback = new MockAuthenticationCallback<>();

        client.userInfo("ACCESS_TOKEN")
                .start(callback);

        assertThat(callback, hasPayloadOfType(UserProfile.class));

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getHeader("Authorization"), is("Bearer ACCESS_TOKEN"));
        assertThat(request.getPath(), equalTo("/userinfo"));
    }

    @Test
    public void shouldFetchUserInfoSync() throws Exception {
        mockAPI.willReturnUserInfo();

        final UserProfile profile = client
                .userInfo("ACCESS_TOKEN")
                .execute();

        assertThat(profile, is(notNullValue()));

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getHeader("Authorization"), is("Bearer ACCESS_TOKEN"));
        assertThat(request.getPath(), equalTo("/userinfo"));
    }

    @Test
    public void shouldLoginWithNativeSocialToken() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.loginWithNativeSocialToken("test-token-value", "test-token-type")
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE));
        assertThat(body, hasEntry("subject_token", "test-token-value"));
        assertThat(body, hasEntry("subject_token_type", "test-token-type"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldLoginWithNativeSocialTokenSync() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        final Credentials credentials = client
                .loginWithNativeSocialToken("test-token-value", "test-token-type")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE));
        assertThat(body, hasEntry("subject_token", "test-token-value"));
        assertThat(body, hasEntry("subject_token_type", "test-token-type"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(credentials, is(notNullValue()));
    }

    @Test
    public void shouldLoginWithPhoneNumberWithCustomConnectionWithOTPGrant() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.loginWithPhoneNumber("+10101010101", "1234", MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP));
        assertThat(body, hasEntry("realm", MY_CONNECTION));
        assertThat(body, hasEntry("username", "+10101010101"));
        assertThat(body, hasEntry("otp", "1234"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldLoginWithPhoneNumberWithOTPGrant() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.loginWithPhoneNumber("+10101010101", "1234")
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP));
        assertThat(body, hasEntry("realm", "sms"));
        assertThat(body, hasEntry("username", "+10101010101"));
        assertThat(body, hasEntry("otp", "1234"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldLoginWithPhoneNumberSyncWithOTPGrant() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        final Credentials credentials = client
                .loginWithPhoneNumber("+10101010101", "1234")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP));
        assertThat(body, hasEntry("realm", "sms"));
        assertThat(body, hasEntry("username", "+10101010101"));
        assertThat(body, hasEntry("otp", "1234"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(credentials, is(notNullValue()));
    }

    @Test
    public void shouldLoginWithEmailOnlyWithCustomConnectionWithOTPGrant() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.loginWithEmail(SUPPORT_AUTH0_COM, "1234", MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP));
        assertThat(body, hasEntry("realm", MY_CONNECTION));
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("otp", "1234"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldLoginWithEmailOnlyWithOTPGrant() throws Exception {
        mockAPI.willReturnSuccessfulLogin();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.loginWithEmail(SUPPORT_AUTH0_COM, "1234")
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP));
        assertThat(body, hasEntry("realm", "email"));
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("otp", "1234"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldLoginWithEmailOnlySyncWithOTPGrant() throws Exception {
        mockAPI.willReturnSuccessfulLogin()
                .willReturnUserInfo();

        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        final Credentials credentials = client
                .loginWithEmail(SUPPORT_AUTH0_COM, "1234")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP));
        assertThat(body, hasEntry("realm", "email"));
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("otp", "1234"));
        assertThat(body, hasEntry("scope", OPENID));

        assertThat(credentials, is(notNullValue()));
    }

    @Test
    public void shouldCreateUser() throws Exception {
        mockAPI.willReturnSuccessfulSignUp();

        final MockAuthenticationCallback<DatabaseUser> callback = new MockAuthenticationCallback<>();
        client.createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("username", SUPPORT));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasPayloadOfType(DatabaseUser.class));
    }

    @Test
    public void shouldCreateUserSync() throws Exception {
        mockAPI.willReturnSuccessfulSignUp();

        final DatabaseUser user = client
                .createUser(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("username", SUPPORT));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(user, is(notNullValue()));
    }

    @Test
    public void shouldCreateUserWithoutUsername() throws Exception {
        mockAPI.willReturnSuccessfulSignUp();

        final MockAuthenticationCallback<DatabaseUser> callback = new MockAuthenticationCallback<>();
        client.createUser(SUPPORT_AUTH0_COM, PASSWORD, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasPayloadOfType(DatabaseUser.class));
    }

    @Test
    public void shouldCreateUserWithoutUsernameSync() throws Exception {
        mockAPI.willReturnSuccessfulSignUp();

        final DatabaseUser user = client
                .createUser(SUPPORT_AUTH0_COM, PASSWORD, MY_CONNECTION)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(user, is(notNullValue()));
    }

    @Test
    public void shouldNotSendNullUsernameOnSignUp() throws Exception {
        mockAPI.willReturnSuccessfulSignUp();

        final MockAuthenticationCallback<DatabaseUser> callback = new MockAuthenticationCallback<>();
        client.createUser(SUPPORT_AUTH0_COM, PASSWORD, null, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasPayloadOfType(DatabaseUser.class));
    }

    @Test
    public void shouldNotSendNullUsernameOnSignUpSync() throws Exception {
        mockAPI.willReturnSuccessfulSignUp();

        final DatabaseUser user = client.createUser(SUPPORT_AUTH0_COM, PASSWORD, null, MY_CONNECTION)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(user, is(notNullValue()));
    }

    @Test
    public void shouldLoginWithUsernameSignedUpUserWithPasswordRealmGrant() throws Exception {
        mockAPI.willReturnSuccessfulSignUp()
                .willReturnSuccessfulLogin();

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);
        client.signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("username", SUPPORT));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasPayloadOfType(Credentials.class));

        final RecordedRequest loginRequest = mockAPI.takeRequest();
        assertThat(loginRequest.getPath(), equalTo("/oauth/token"));

        Map<String, String> loginBody = bodyFromRequest(loginRequest);
        assertThat(loginBody, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(loginBody, hasEntry("password", PASSWORD));
        assertThat(loginBody, hasEntry("realm", MY_CONNECTION));
        assertThat(loginBody, not(hasKey("scope")));
        assertThat(loginBody, not(hasKey("connection")));
    }

    @Test
    public void shouldSignUpUserWithCustomFields() throws Exception {
        mockAPI.willReturnSuccessfulSignUp()
                .willReturnSuccessfulLogin();

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        final Map<String, String> custom = ParameterBuilder.newBuilder()
                .set("first_name", FIRST_NAME)
                .set("last_name", LAST_NAME)
                .set("company", COMPANY)
                .asDictionary();

        client.signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
                .addSignUpParameters(custom)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("username", SUPPORT));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));
        assertThat(body, hasEntry("first_name", FIRST_NAME));
        assertThat(body, hasEntry("last_name", LAST_NAME));
        assertThat(body, hasEntry("company", COMPANY));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldSignUpUserSync() throws Exception {
        mockAPI.willReturnSuccessfulSignUp()
                .willReturnSuccessfulLogin()
                .willReturnUserInfo();

        final Credentials credentials = client
                .signUp(SUPPORT_AUTH0_COM, PASSWORD, SUPPORT, MY_CONNECTION)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("username", SUPPORT));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(credentials, is(notNullValue()));

        final RecordedRequest loginRequest = mockAPI.takeRequest();
        assertThat(loginRequest.getPath(), equalTo("/oauth/token"));

        Map<String, String> loginBody = bodyFromRequest(loginRequest);
        assertThat(loginBody, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(loginBody, hasEntry("password", PASSWORD));
        assertThat(loginBody, hasEntry("realm", MY_CONNECTION));
        assertThat(loginBody, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm"));
        assertThat(loginBody, hasEntry("client_id", CLIENT_ID));
    }

    @Test
    public void shouldSignUpUserWithoutUsername() throws Exception {
        mockAPI.willReturnSuccessfulSignUp()
                .willReturnSuccessfulLogin()
                .willReturnUserInfo();

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.signUp(SUPPORT_AUTH0_COM, PASSWORD, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasPayloadOfType(Credentials.class));

        final RecordedRequest loginRequest = mockAPI.takeRequest();
        assertThat(loginRequest.getPath(), equalTo("/oauth/token"));

        Map<String, String> loginBody = bodyFromRequest(loginRequest);
        assertThat(loginBody, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(loginBody, hasEntry("password", PASSWORD));
        assertThat(loginBody, hasEntry("realm", MY_CONNECTION));
        assertThat(loginBody, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm"));
        assertThat(loginBody, hasEntry("client_id", CLIENT_ID));
    }

    @Test
    public void shouldLoginSignedUpUserWithPasswordRealmGrant() throws Exception {
        mockAPI.willReturnSuccessfulSignUp()
                .willReturnSuccessfulLogin()
                .willReturnUserInfo();

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);
        client.signUp(SUPPORT_AUTH0_COM, PASSWORD, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/signup"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, hasEntry("password", PASSWORD));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasPayloadOfType(Credentials.class));

        final RecordedRequest loginRequest = mockAPI.takeRequest();
        assertThat(loginRequest.getPath(), equalTo("/oauth/token"));

        Map<String, String> loginBody = bodyFromRequest(loginRequest);
        assertThat(loginBody, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(loginBody, hasEntry("password", PASSWORD));
        assertThat(loginBody, hasEntry("realm", MY_CONNECTION));
        assertThat(loginBody, not(hasKey("scope")));
        assertThat(loginBody, not(hasKey("connection")));
    }

    @Test
    public void shouldChangePassword() throws Exception {
        mockAPI.willReturnSuccessfulChangePassword();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/change_password"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldChangePasswordSync() throws Exception {
        mockAPI.willReturnSuccessfulChangePassword();

        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/change_password"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, hasEntry("connection", MY_CONNECTION));
    }

    @Test
    public void shouldRequestChangePassword() throws Exception {
        mockAPI.willReturnSuccessfulChangePassword();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/change_password"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, not(hasKey("password")));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldRequestChangePasswordSync() throws Exception {
        mockAPI.willReturnSuccessfulChangePassword();

        client.resetPassword(SUPPORT_AUTH0_COM, MY_CONNECTION)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/dbconnections/change_password"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, not(hasKey("username")));
        assertThat(body, not(hasKey("password")));
        assertThat(body, hasEntry("connection", MY_CONNECTION));
    }

    @Test
    public void shouldSendEmailCodeWithCustomConnection() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.CODE, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "code"));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendEmailCode() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.CODE)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "code"));
        assertThat(body, hasEntry("connection", "email"));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendEmailCodeSync() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.CODE)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "code"));
        assertThat(body, hasEntry("connection", "email"));
    }

    @Test
    public void shouldSendEmailLink() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.WEB_LINK)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "link"));
        assertThat(body, hasEntry("connection", "email"));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendEmailLinkWithCustomConnection() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.WEB_LINK, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "link"));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendEmailLinkSync() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.WEB_LINK)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "link"));
        assertThat(body, hasEntry("connection", "email"));
    }

    @Test
    public void shouldSendEmailLinkAndroidWithCustomConnection() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.ANDROID_LINK, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "link_android"));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendEmailLinkAndroid() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.ANDROID_LINK)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "link_android"));
        assertThat(body, hasEntry("connection", "email"));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendEmailLinkAndroidSync() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        client.passwordlessWithEmail(SUPPORT_AUTH0_COM, PasswordlessType.ANDROID_LINK)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("email", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("send", "link_android"));
        assertThat(body, hasEntry("connection", "email"));
    }

    @Test
    public void shouldSendSMSCodeWithCustomConnection() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithSMS("+1123123123", PasswordlessType.CODE, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "code"));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendSMSCode() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithSMS("+1123123123", PasswordlessType.CODE)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "code"));
        assertThat(body, hasEntry("connection", "sms"));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendSMSCodeSync() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        client.passwordlessWithSMS("+1123123123", PasswordlessType.CODE)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "code"));
        assertThat(body, hasEntry("connection", "sms"));
    }

    @Test
    public void shouldSendSMSLinkWithCustomConnection() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithSMS("+1123123123", PasswordlessType.WEB_LINK, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "link"));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendSMSLink() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithSMS("+1123123123", PasswordlessType.WEB_LINK)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "link"));
        assertThat(body, hasEntry("connection", "sms"));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendSMSLinkSync() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        client.passwordlessWithSMS("+1123123123", PasswordlessType.WEB_LINK)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "link"));
        assertThat(body, hasEntry("connection", "sms"));
    }

    @Test
    public void shouldSendSMSLinkAndroidWithCustomConnection() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithSMS("+1123123123", PasswordlessType.ANDROID_LINK, MY_CONNECTION)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "link_android"));
        assertThat(body, hasEntry("connection", MY_CONNECTION));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendSMSLinkAndroid() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.passwordlessWithSMS("+1123123123", PasswordlessType.ANDROID_LINK)
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "link_android"));
        assertThat(body, hasEntry("connection", "sms"));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldSendSMSLinkAndroidSync() throws Exception {
        mockAPI.willReturnSuccessfulPasswordlessStart();

        client.passwordlessWithSMS("+1123123123", PasswordlessType.ANDROID_LINK)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/passwordless/start"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("phone_number", "+1123123123"));
        assertThat(body, hasEntry("send", "link_android"));
        assertThat(body, hasEntry("connection", "sms"));
    }

    @Test
    public void shouldFetchJsonWebKeys() throws Exception {
        mockAPI.willReturnEmptyJsonWebKeys();

        MockAuthenticationCallback<Map<String, PublicKey>> callback = new MockAuthenticationCallback<>();
        client.fetchJsonWebKeys()
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/.well-known/jwks.json"));
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));

        assertThat(callback, hasPayload(Collections.<String, PublicKey>emptyMap()));
    }

    @Test
    public void shouldFetchJsonWebKeysSync() throws Exception {
        mockAPI.willReturnEmptyJsonWebKeys();

        Map<String, PublicKey> result = client.fetchJsonWebKeys()
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/.well-known/jwks.json"));
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));

        assertThat(result, is(notNullValue()));
        assertThat(result, is(Collections.<String, PublicKey>emptyMap()));
    }

    @Test
    public void shouldFetchProfileAfterLoginRequest() throws Exception {
        mockAPI.willReturnSuccessfulLogin()
                .willReturnUserInfo();

        MockAuthenticationCallback<Authentication> callback = new MockAuthenticationCallback<>();
        client.getProfileAfter(client.login(SUPPORT_AUTH0_COM, "voidpassword", MY_CONNECTION))
                .start(callback);

        final RecordedRequest firstRequest = mockAPI.takeRequest();
        assertThat(firstRequest.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(firstRequest);
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("password", "voidpassword"));
        assertThat(body, hasEntry("realm", MY_CONNECTION));
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm"));

        final RecordedRequest secondRequest = mockAPI.takeRequest();
        assertThat(secondRequest.getHeader("Authorization"), is("Bearer " + AuthenticationAPI.ACCESS_TOKEN));
        assertThat(secondRequest.getPath(), equalTo("/userinfo"));

        assertThat(callback, hasPayloadOfType(Authentication.class));
    }


    @Test
    public void shouldRevokeToken() throws Exception {
        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        mockAPI.willReturnSuccessfulEmptyBody();
        final MockAuthenticationCallback<Unit> callback = new MockAuthenticationCallback<>();
        client.revokeToken("refreshToken")
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/revoke"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("token", "refreshToken"));

        assertThat(callback, hasNoError());
    }

    @Test
    public void shouldRevokeTokenSync() throws Exception {
        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        mockAPI.willReturnSuccessfulEmptyBody();
        client.revokeToken("refreshToken")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/revoke"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("token", "refreshToken"));
    }

    @Test
    public void shouldRenewAuthWithOAuthToken() throws Exception {
        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        mockAPI.willReturnSuccessfulLogin();
        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.renewAuth("refreshToken")
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("refresh_token", "refreshToken"));
        assertThat(body, hasEntry("grant_type", "refresh_token"));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldRenewAuthWithOAuthTokenSync() throws Exception {
        Auth0 auth0 = new Auth0(CLIENT_ID, mockAPI.getDomain(), mockAPI.getDomain());
        AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);

        mockAPI.willReturnSuccessfulLogin();
        Credentials credentials = client.renewAuth("refreshToken")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getHeader("Accept-Language"), is(getDefaultLocale()));
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("refresh_token", "refreshToken"));
        assertThat(body, hasEntry("grant_type", "refresh_token"));

        assertThat(credentials, is(notNullValue()));
    }

    @Test
    public void shouldFetchProfileSyncAfterLoginRequest() throws Exception {
        mockAPI.willReturnSuccessfulLogin()
                .willReturnUserInfo();

        Authentication authentication = client.getProfileAfter(client.login(SUPPORT_AUTH0_COM, "voidpassword", MY_CONNECTION))
                .execute();

        final RecordedRequest firstRequest = mockAPI.takeRequest();
        assertThat(firstRequest.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(firstRequest);
        assertThat(body, hasEntry("username", SUPPORT_AUTH0_COM));
        assertThat(body, hasEntry("password", "voidpassword"));
        assertThat(body, hasEntry("realm", MY_CONNECTION));
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("grant_type", "http://auth0.com/oauth/grant-type/password-realm"));

        final RecordedRequest secondRequest = mockAPI.takeRequest();
        assertThat(secondRequest.getHeader("Authorization"), is("Bearer " + AuthenticationAPI.ACCESS_TOKEN));
        assertThat(secondRequest.getPath(), equalTo("/userinfo"));

        assertThat(authentication, is(notNullValue()));
    }

    @Test
    public void shouldGetOAuthTokensUsingCodeVerifier() throws Exception {
        mockAPI.willReturnTokens()
                .willReturnUserInfo();

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.token("code", "http://redirect.uri")
                .setCodeVerifier("codeVerifier")
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE));
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("code", "code"));
        assertThat(body, hasEntry("code_verifier", "codeVerifier"));
        assertThat(body, hasEntry("redirect_uri", "http://redirect.uri"));

        assertThat(callback, hasPayloadOfType(Credentials.class));
    }

    @Test
    public void shouldParseUnauthorizedPKCEError() throws Exception {
        mockAPI.willReturnPlainTextUnauthorized();

        final MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        client.token("code", "http://redirect.uri")
                .setCodeVerifier("codeVerifier")
                .start(callback);

        final RecordedRequest request = mockAPI.takeRequest();
        assertThat(request.getPath(), equalTo("/oauth/token"));

        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE));
        assertThat(body, hasEntry("client_id", CLIENT_ID));
        assertThat(body, hasEntry("code", "code"));
        assertThat(body, hasEntry("code_verifier", "codeVerifier"));
        assertThat(body, hasEntry("redirect_uri", "http://redirect.uri"));

        assertThat(callback, hasError(Credentials.class));
        assertThat(callback.getError().getDescription(), is(equalTo("Unauthorized")));
    }

    private Map<String, String> bodyFromRequest(RecordedRequest request) {
        final Type mapType = new TypeToken<Map<String, String>>() {
        }.getType();
        return gson.fromJson(request.getBody().readUtf8(), mapType);
    }

    private String getDefaultLocale() {
        String language = Locale.getDefault().toString();
        return !language.isEmpty() ? language : DEFAULT_LOCALE_IF_MISSING;
    }
}