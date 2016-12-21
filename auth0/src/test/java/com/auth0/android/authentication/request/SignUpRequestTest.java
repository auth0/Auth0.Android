package com.auth0.android.authentication.request;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.DatabaseUser;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Map;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class SignUpRequestTest {

    private DatabaseConnectionRequest dbMockRequest;
    private AuthenticationRequest authenticationMockRequest;
    private SignUpRequest signUpRequest;

    @Before
    public void setUp() throws Exception {
        dbMockRequest = mock(DatabaseConnectionRequest.class);
        authenticationMockRequest = mock(AuthenticationRequest.class);
        signUpRequest = new SignUpRequest(dbMockRequest, authenticationMockRequest);
    }

    @Test
    public void shouldAddSignUpParameters() throws Exception {
        final Map params = mock(Map.class);
        final SignUpRequest req = signUpRequest.addSignUpParameters(params);
        verify(dbMockRequest).addParameters(params);
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldAddAuthenticationParameters() throws Exception {
        final Map params = mock(Map.class);
        final SignUpRequest req = signUpRequest.addAuthenticationParameters(params);
        verify(authenticationMockRequest).addAuthenticationParameters(params);
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldSetScope() throws Exception {
        final SignUpRequest req = signUpRequest.setScope("oauth2 offline_access profile");
        verify(authenticationMockRequest).setScope("oauth2 offline_access profile");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldSetAudience() throws Exception {
        final AuthenticationRequest req = signUpRequest.setAudience("https://domain.auth0.com/api");
        verify(authenticationMockRequest).setAudience("https://domain.auth0.com/api");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, Matchers.<AuthenticationRequest>is(signUpRequest));
    }

    @Test
    public void shouldSetDevice() throws Exception {
        final AuthenticationRequest req = signUpRequest.setDevice("nexus-5x");
        verify(authenticationMockRequest).setDevice("nexus-5x");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, Matchers.<AuthenticationRequest>is(signUpRequest));
    }

    @Test
    public void shouldSetGrantType() throws Exception {
        final AuthenticationRequest req = signUpRequest.setGrantType("token");
        verify(authenticationMockRequest).setGrantType("token");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, Matchers.<AuthenticationRequest>is(signUpRequest));
    }

    @Test
    public void shouldSetAccessToken() throws Exception {
        final AuthenticationRequest req = signUpRequest.setAccessToken("super-access-token");
        verify(authenticationMockRequest).setAccessToken("super-access-token");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, Matchers.<AuthenticationRequest>is(signUpRequest));
    }

    @Test
    public void shouldSetConnection() throws Exception {
        final SignUpRequest req = signUpRequest.setConnection("my-connection");
        verify(dbMockRequest).setConnection("my-connection");
        verify(authenticationMockRequest).setConnection("my-connection");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldSetRealm() throws Exception {
        final SignUpRequest req = signUpRequest.setRealm("users");
        verify(dbMockRequest).setConnection("users");
        verify(authenticationMockRequest).setRealm("users");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(signUpRequest));
    }

    @Test
    public void shouldReturnCredentialsAfterStartingTheRequest() throws Exception {
        final DatabaseUser user = mock(DatabaseUser.class);
        final Credentials credentials = mock(Credentials.class);
        final DatabaseConnectionRequestMock dbRequestMock = new DatabaseConnectionRequestMock(user, null);
        final AuthenticationRequestMock authenticationRequestMock = new AuthenticationRequestMock(credentials, null);
        final BaseCallback callback = mock(BaseCallback.class);

        signUpRequest = new SignUpRequest(dbRequestMock, authenticationRequestMock);
        signUpRequest.start(callback);

        assertTrue(dbRequestMock.isStarted());
        assertTrue(authenticationRequestMock.isStarted());
        verify(callback).onSuccess(credentials);
    }

    @Test
    public void shouldReturnErrorAfterStartingTheRequestIfDatabaseRequestFails() throws Exception {
        final AuthenticationException error = mock(AuthenticationException.class);
        final Credentials credentials = mock(Credentials.class);
        final DatabaseConnectionRequestMock dbRequestMock = new DatabaseConnectionRequestMock(null, error);
        final AuthenticationRequestMock authenticationRequestMock = new AuthenticationRequestMock(credentials, null);
        final BaseCallback callback = mock(BaseCallback.class);

        signUpRequest = new SignUpRequest(dbRequestMock, authenticationRequestMock);
        signUpRequest.start(callback);

        assertTrue(dbRequestMock.isStarted());
        assertFalse(authenticationRequestMock.isStarted());
        verify(callback).onFailure(error);
    }

    @Test
    public void shouldReturnErrorAfterStartingTheRequestIfAuthenticationRequestFails() throws Exception {
        final DatabaseUser user = mock(DatabaseUser.class);
        final AuthenticationException error = mock(AuthenticationException.class);
        final DatabaseConnectionRequestMock dbRequestMock = new DatabaseConnectionRequestMock(user, null);
        final AuthenticationRequestMock authenticationRequestMock = new AuthenticationRequestMock(null, error);
        final BaseCallback callback = mock(BaseCallback.class);

        signUpRequest = new SignUpRequest(dbRequestMock, authenticationRequestMock);
        signUpRequest.start(callback);

        assertTrue(dbRequestMock.isStarted());
        assertTrue(authenticationRequestMock.isStarted());
        verify(callback).onFailure(error);
    }

    @Test
    public void shouldExecuteTheRequest() throws Exception {
        when(dbMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return null;
            }
        });
        final Credentials credentials = mock(Credentials.class);
        when(authenticationMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return credentials;
            }
        });
        final Credentials executeResult = signUpRequest.execute();

        verify(dbMockRequest).execute();
        verify(authenticationMockRequest).execute();
        Assert.assertThat(executeResult, is(notNullValue()));
        Assert.assertThat(executeResult, is(credentials));
    }

}