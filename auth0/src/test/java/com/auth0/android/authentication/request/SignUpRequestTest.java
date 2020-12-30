package com.auth0.android.authentication.request;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.DatabaseUser;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;

import java.util.HashMap;
import java.util.Map;

import static junit.framework.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class SignUpRequestTest {

    private DatabaseConnectionRequest dbMockRequest;
    private AuthenticationRequest authenticationMockRequest;
    private SignUpRequest signUpRequest;

    @Before
    public void setUp() {
        dbMockRequest = mock(DatabaseConnectionRequest.class);
        authenticationMockRequest = mock(AuthenticationRequest.class);
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
        assertThat(req, Matchers.<AuthenticationRequest>is(signUpRequest));
    }

    @Test
    public void shouldSetGrantType() {
        final AuthenticationRequest req = signUpRequest.setGrantType("token");
        verify(authenticationMockRequest).setGrantType("token");
        assertThat(req, is(notNullValue()));
        assertThat(req, Matchers.<AuthenticationRequest>is(signUpRequest));
    }

    @Test
    public void shouldSetConnection() {
        final SignUpRequest req = signUpRequest.setConnection("my-connection");
        verify(dbMockRequest).setConnection("my-connection");
        verify(authenticationMockRequest).setConnection("my-connection");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldSetRealm() {
        final SignUpRequest req = signUpRequest.setRealm("users");
        verify(dbMockRequest).setConnection("users");
        verify(authenticationMockRequest).setRealm("users");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldReturnCredentialsAfterStartingTheRequest() {
        final DatabaseUser user = mock(DatabaseUser.class);
        final Credentials credentials = mock(Credentials.class);
        final DatabaseConnectionRequestMock dbRequestMock = new DatabaseConnectionRequestMock(user, null);
        final BaseCallback callback = mock(BaseCallback.class);

        doAnswer(invocation -> {
            ((BaseCallback)invocation.getArguments()[0]).onSuccess(credentials);
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
        final Credentials credentials = mock(Credentials.class);
        final DatabaseConnectionRequestMock dbRequestMock = new DatabaseConnectionRequestMock(null, error);
        final BaseCallback callback = mock(BaseCallback.class);

        signUpRequest = new SignUpRequest(dbRequestMock, authenticationMockRequest);
        signUpRequest.start(callback);

        assertTrue(dbRequestMock.isStarted());
        verify(callback).onFailure(error);
    }

    @Test
    public void shouldReturnErrorAfterStartingTheRequestIfAuthenticationRequestFails() {
        final DatabaseUser user = mock(DatabaseUser.class);
        final AuthenticationException error = mock(AuthenticationException.class);
        final DatabaseConnectionRequestMock dbRequestMock = new DatabaseConnectionRequestMock(user, null);
        final BaseCallback callback = mock(BaseCallback.class);


        doAnswer(invocation -> {
            ((BaseCallback)invocation.getArguments()[0]).onFailure(error);
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
        when(dbMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                return null;
            }
        });
        final Credentials credentials = mock(Credentials.class);
        when(authenticationMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                return credentials;
            }
        });
        final Credentials executeResult = signUpRequest.execute();

        verify(dbMockRequest).execute();
        verify(authenticationMockRequest).execute();
        assertThat(executeResult, is(notNullValue()));
        assertThat(executeResult, is(credentials));
    }

}