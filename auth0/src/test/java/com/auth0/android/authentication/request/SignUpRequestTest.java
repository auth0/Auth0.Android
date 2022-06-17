package com.auth0.android.authentication.request;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.Callback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.Request;
import com.auth0.android.request.SignUpRequest;
import com.auth0.android.request.internal.BaseAuthenticationRequest;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.DatabaseUser;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.HashMap;
import java.util.Map;

import static junit.framework.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class SignUpRequestTest {

    private Request dbMockRequest;
    private BaseAuthenticationRequest authenticationMockRequest;
    private SignUpRequest signUpRequest;

    @Before
    public void setUp() {
        dbMockRequest = mock(Request.class);
        authenticationMockRequest = mock(BaseAuthenticationRequest.class);
        signUpRequest = new SignUpRequest(dbMockRequest, authenticationMockRequest);
    }

    @Test
    public void shouldAddSignUpParameters() {
        final Map params = mock(Map.class);
        final SignUpRequest req = signUpRequest.addSignUpParameters(params);
        verify(dbMockRequest).addParameters(params);
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldAddAuthenticationParameters() {
        final Map params = mock(Map.class);
        final SignUpRequest req = signUpRequest.addAuthenticationParameters(params);
        verify(authenticationMockRequest).addParameters(params);
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldSetScope() {
        final SignUpRequest req = signUpRequest.setScope("oauth2 offline_access profile");
        verify(authenticationMockRequest).setScope("oauth2 offline_access profile");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldAddHeader() {
        final SignUpRequest req = signUpRequest.addHeader("auth", "val123");
        verify(authenticationMockRequest).addHeader(eq("auth"), eq("val123"));
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldAddParameter() {
        final SignUpRequest req = signUpRequest.addParameter("param", "val123");
        verify(authenticationMockRequest).addParameter(eq("param"), eq("val123"));
        verify(dbMockRequest).addParameter(eq("param"), eq("val123"));
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldAddParameters() {
        Map<String, String> params = new HashMap<>();
        params.put("param1", "val1");
        params.put("param2", "val2");

        final SignUpRequest req = signUpRequest.addParameters(params);
        verify(authenticationMockRequest).addParameters(eq(params));
        verify(dbMockRequest).addParameters(eq(params));
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldSetAudience() {
        final AuthenticationRequest req = signUpRequest.setAudience("https://domain.auth0.com/api");
        verify(authenticationMockRequest).setAudience("https://domain.auth0.com/api");
        assertThat(req, is(notNullValue()));
        assertThat(req, Matchers.is(signUpRequest));
    }

    @Test
    public void shouldSetGrantType() {
        final AuthenticationRequest req = signUpRequest.setGrantType("token");
        verify(authenticationMockRequest).setGrantType("token");
        assertThat(req, is(notNullValue()));
        assertThat(req, Matchers.is(signUpRequest));
    }

    @Test
    public void shouldSetConnection() {
        final SignUpRequest req = signUpRequest.setConnection("my-connection");
        verify(dbMockRequest).addParameter("connection", "my-connection");
        verify(authenticationMockRequest).setConnection("my-connection");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldSetRealm() {
        final SignUpRequest req = signUpRequest.setRealm("users");
        verify(dbMockRequest).addParameter("connection", "users");
        verify(authenticationMockRequest).setRealm("users");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldReturnCredentialsAfterStartingTheRequest() {
        final DatabaseUser user = mock(DatabaseUser.class);
        final Credentials credentials = mock(Credentials.class);
        final RequestMock dbRequestMock = new RequestMock(user, null);
        final Callback callback = mock(Callback.class);

        doAnswer(invocation -> {
            ((Callback) invocation.getArguments()[0]).onSuccess(credentials);
            return null;
        }).when(authenticationMockRequest).start(callback);


        signUpRequest = new SignUpRequest(dbRequestMock, authenticationMockRequest);
        signUpRequest.start(callback);

        assertTrue(dbRequestMock.isStarted());
        verify(authenticationMockRequest).start(callback);
        verify(callback).onSuccess(credentials);
    }

    @Test
    public void shouldReturnErrorAfterStartingTheRequestIfDatabaseRequestFails() {
        final AuthenticationException error = mock(AuthenticationException.class);
        final RequestMock dbRequestMock = new RequestMock<>(null, error);
        final Callback callback = mock(Callback.class);

        signUpRequest = new SignUpRequest(dbRequestMock, authenticationMockRequest);
        signUpRequest.start(callback);

        assertTrue(dbRequestMock.isStarted());
        verify(callback).onFailure(error);
    }

    @Test
    public void shouldReturnErrorAfterStartingTheRequestIfAuthenticationRequestFails() {
        final DatabaseUser user = mock(DatabaseUser.class);
        final AuthenticationException error = mock(AuthenticationException.class);
        final RequestMock dbRequestMock = new RequestMock<>(user, null);
        final Callback callback = mock(Callback.class);

        doAnswer(invocation -> {
            ((Callback) invocation.getArguments()[0]).onFailure(error);
            return null;
        }).when(authenticationMockRequest).start(callback);

        signUpRequest = new SignUpRequest(dbRequestMock, authenticationMockRequest);
        signUpRequest.start(callback);

        assertTrue(dbRequestMock.isStarted());
        verify(authenticationMockRequest).start(callback);
        verify(callback).onFailure(error);
    }

    @Test
    public void shouldExecuteTheRequest() {
        when(dbMockRequest.execute()).thenAnswer(invocation -> null);
        final Credentials credentials = mock(Credentials.class);
        when(authenticationMockRequest.execute()).thenAnswer(invocation -> credentials);
        final Credentials executeResult = signUpRequest.execute();

        verify(dbMockRequest).execute();
        verify(authenticationMockRequest).execute();
        assertThat(executeResult, is(notNullValue()));
        assertThat(executeResult, is(credentials));
    }

    @Test
    public void shouldSetClaimValidationParametersForAuthenticationRequest() {
        final SignUpRequest req = signUpRequest
                .validateClaims()
                .withIdTokenVerificationIssuer("custom")
                .withIdTokenVerificationLeeway(0);
        verify(authenticationMockRequest, times(1)).validateClaims();
        verify(authenticationMockRequest, times(1)).withIdTokenVerificationIssuer("custom");
        verify(authenticationMockRequest, times(1)).withIdTokenVerificationLeeway(0);
    }
}