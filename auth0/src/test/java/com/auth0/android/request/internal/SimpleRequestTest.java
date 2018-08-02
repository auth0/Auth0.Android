package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.RequestBodyBuildException;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.authentication.JwtVerifier;
import com.auth0.android.authentication.TokenVerificationException;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.DatabaseUser;
import com.auth0.android.util.AuthenticationAPI;
import com.auth0.android.util.MockAuthenticationCallback;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;

import org.hamcrest.core.IsInstanceOf;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;

import static com.auth0.android.util.AuthenticationCallbackMatcher.hasError;
import static com.auth0.android.util.AuthenticationCallbackMatcher.hasPayloadOfType;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class SimpleRequestTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private AuthenticationAPI mockAPI;

    @Before
    public void setUp() throws Exception {
        mockAPI = new AuthenticationAPI();
    }

    @After
    public void tearDown() throws Exception {
        mockAPI.shutdown();
    }

    private <T> SimpleRequest<T, AuthenticationException> createRequest(Class<T> clazz) {
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment("oauth")
                .addPathSegment("token")
                .build();
        return new SimpleRequest<>(url, new OkHttpClient(), GsonProvider.buildGson(), "POST", clazz, new AuthenticationErrorBuilder());
    }

    @Test
    public void shouldThrowWhenRequestExecutionFails() throws Exception {
        //Create a request that will fail when executed
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment("oauth")
                .addPathSegment("token")
                .build();

        exception.expect(AuthenticationException.class);
        exception.expectCause(IsInstanceOf.<Throwable>instanceOf(Auth0Exception.class));
        exception.expectMessage("Failed to execute request to " + url);

        OkHttpClient client = mock(OkHttpClient.class);
        doThrow(IOException.class).when(client).newCall(any(Request.class));
        SimpleRequest<Credentials, AuthenticationException> requestSync = new SimpleRequest<>(url, client, new Gson(), "POST", Credentials.class, new AuthenticationErrorBuilder());

        mockAPI.willReturnSuccessfulLogin();
        requestSync.addParameter("scope", "openid")
                .execute();
        mockAPI.takeRequest();
    }

    @Test
    public void shouldCallOnFailureWhenRequestCreationFails() throws Exception {
        //Create a request that will fail when the body gets created
        SimpleRequest<Credentials, AuthenticationException> request = createRequest(Credentials.class);
        SimpleRequest<Credentials, AuthenticationException> requestAsync = spy(request);
        doThrow(RequestBodyBuildException.class).when(requestAsync).doBuildRequest();

        MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        requestAsync.addParameter("scope", "openid")
                .start(callback);
        assertThat(callback, hasError(Credentials.class));
        AuthenticationException error = callback.getError();
        assertThat(error, instanceOf(AuthenticationException.class));
        assertThat(error.getCause(), instanceOf(Auth0Exception.class));
        assertThat(error.getMessage(), is("Error parsing the request body"));
    }

    @Test
    public void shouldThrowWhenResponseCannotBeParsed() throws Exception {
        exception.expect(AuthenticationException.class);
        exception.expectCause(IsInstanceOf.<Throwable>instanceOf(Auth0Exception.class));
        exception.expectMessage("Failed to parse a successful response");


        //Create a request that will fail when parsed
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment("oauth")
                .addPathSegment("token")
                .build();

        TypeAdapter<Credentials> typeAdapter = mock(TypeAdapter.class);
        doThrow(IOException.class).when(typeAdapter).fromJson(anyString());
        Gson gson = new GsonBuilder().registerTypeAdapter(Credentials.class, typeAdapter).create();
        SimpleRequest<Credentials, AuthenticationException> requestSync = new SimpleRequest<>(url, new OkHttpClient(), gson, "POST", Credentials.class, new AuthenticationErrorBuilder());

        mockAPI.willReturnSuccessfulLogin();
        requestSync.addParameter("scope", "openid")
                .execute();
        mockAPI.takeRequest();
    }

    @Test
    public void shouldCallOnFailureWhenResponseCannotBeParsed() throws Exception {
        //Create a request that will fail when parsed
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment("oauth")
                .addPathSegment("token")
                .build();

        TypeAdapter<Credentials> typeAdapter = mock(TypeAdapter.class);
        doThrow(IOException.class).when(typeAdapter).fromJson(anyString());
        Gson gson = new GsonBuilder().registerTypeAdapter(Credentials.class, typeAdapter).create();
        SimpleRequest<Credentials, AuthenticationException> requestAsync = new SimpleRequest<>(url, new OkHttpClient(), gson, "POST", Credentials.class, new AuthenticationErrorBuilder());

        MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        mockAPI.willReturnSuccessfulLogin();
        requestAsync.addParameter("scope", "openid")
                .start(callback);
        assertThat(callback, hasError(Credentials.class));
        AuthenticationException error = callback.getError();
        assertThat(error, instanceOf(AuthenticationException.class));
        assertThat(error.getCause(), instanceOf(Auth0Exception.class));
        assertThat(error.getMessage(), is("Failed to parse a successful response"));
        mockAPI.takeRequest();
    }

    @Test
    public void shouldThrowWhenIdTokenVerificationFails() throws Exception {
        exception.expect(AuthenticationException.class);
        exception.expectCause(IsInstanceOf.<Throwable>instanceOf(TokenVerificationException.class));
        exception.expectMessage("The received Id Token is not valid");

        SimpleRequest<Credentials, AuthenticationException> requestSync = createRequest(Credentials.class);
        JwtVerifier verifierSync = mock(JwtVerifier.class);
        doThrow(TokenVerificationException.class).when(verifierSync).verify(AuthenticationAPI.ID_TOKEN);

        mockAPI.willReturnSuccessfulLogin();
        requestSync.setJwtVerifier(verifierSync);
        requestSync.addParameter("scope", "openid")
                .execute();
        mockAPI.takeRequest();
    }

    @Test
    public void shouldCallOnFailureWhenIdTokenVerificationFails() throws Exception {
        SimpleRequest<Credentials, AuthenticationException> requestAsync = createRequest(Credentials.class);
        JwtVerifier verifierAsync = mock(JwtVerifier.class);
        doThrow(TokenVerificationException.class).when(verifierAsync).verify(AuthenticationAPI.ID_TOKEN);

        MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        mockAPI.willReturnSuccessfulLogin();
        requestAsync.setJwtVerifier(verifierAsync);
        requestAsync.addParameter("scope", "openid")
                .start(callback);
        assertThat(callback, hasError(Credentials.class));
        AuthenticationException error = callback.getError();
        assertThat(error, instanceOf(AuthenticationException.class));
        assertThat(error.getCause(), instanceOf(TokenVerificationException.class));
        assertThat(error.getMessage(), is("The received Id Token is not valid"));
        mockAPI.takeRequest();
    }

    @Test
    public void shouldPerformIdTokenVerificationWhenVerifierIsSet() throws Exception {
        //Sync
        SimpleRequest<Credentials, AuthenticationException> requestSync = createRequest(Credentials.class);
        JwtVerifier verifierSync = mock(JwtVerifier.class);
        mockAPI.willReturnSuccessfulLogin();
        requestSync.setJwtVerifier(verifierSync);
        requestSync.addParameter("scope", "openid")
                .execute();
        mockAPI.takeRequest();
        verify(verifierSync).verify(AuthenticationAPI.ID_TOKEN);


        //Async
        SimpleRequest<Credentials, AuthenticationException> requestAsync = createRequest(Credentials.class);
        MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        JwtVerifier verifierAsync = mock(JwtVerifier.class);
        mockAPI.willReturnSuccessfulLogin();
        requestAsync.setJwtVerifier(verifierAsync);
        requestAsync.addParameter("scope", "openid")
                .start(callback);
        assertThat(callback, hasPayloadOfType(Credentials.class));
        mockAPI.takeRequest();
        verify(verifierAsync).verify(AuthenticationAPI.ID_TOKEN);
    }

    @Test
    public void shouldSkipIdTokenVerificationWhenIdTokenNotPresent() throws Exception {
        //Sync
        SimpleRequest<Credentials, AuthenticationException> requestSync = createRequest(Credentials.class);
        JwtVerifier verifierSync = mock(JwtVerifier.class);
        mockAPI.willReturnSuccessfulLoginWithoutIdToken();
        requestSync.setJwtVerifier(verifierSync);
        requestSync.addParameter("scope", "openid")
                .execute();
        mockAPI.takeRequest();
        verify(verifierSync, never()).verify(anyString());


        //Async
        SimpleRequest<Credentials, AuthenticationException> requestAsync = createRequest(Credentials.class);
        MockAuthenticationCallback<Credentials> callback = new MockAuthenticationCallback<>();
        JwtVerifier verifierAsync = mock(JwtVerifier.class);
        mockAPI.willReturnSuccessfulLoginWithoutIdToken();
        requestAsync.setJwtVerifier(verifierAsync);
        requestAsync.addParameter("scope", "openid")
                .start(callback);
        assertThat(callback, hasPayloadOfType(Credentials.class));
        mockAPI.takeRequest();
        verify(verifierAsync, never()).verify(anyString());
    }

    @Test
    public void shouldSkipIdTokenVerificationWhenPayloadIsNotCredentials() throws Exception {
        //Sync
        SimpleRequest<DatabaseUser, AuthenticationException> requestSync = createRequest(DatabaseUser.class);
        JwtVerifier verifierSync = mock(JwtVerifier.class);
        mockAPI.willReturnSuccessfulSignUp();
        requestSync.setJwtVerifier(verifierSync);
        requestSync.addParameter("scope", "openid")
                .execute();
        mockAPI.takeRequest();
        verify(verifierSync, never()).verify(anyString());


        //Async
        SimpleRequest<DatabaseUser, AuthenticationException> requestAsync = createRequest(DatabaseUser.class);
        MockAuthenticationCallback<DatabaseUser> callback = new MockAuthenticationCallback<>();
        JwtVerifier verifierAsync = mock(JwtVerifier.class);
        mockAPI.willReturnSuccessfulSignUp();
        requestAsync.setJwtVerifier(verifierAsync);
        requestAsync.addParameter("scope", "openid")
                .start(callback);
        assertThat(callback, hasPayloadOfType(DatabaseUser.class));
        mockAPI.takeRequest();
        verify(verifierAsync, never()).verify(anyString());
    }

}