package com.auth0.android.authentication.request;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.Callback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.ProfileRequest;
import com.auth0.android.request.Request;
import com.auth0.android.result.Authentication;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.UserProfile;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyObject;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class ProfileRequestTest {

    private AuthenticationRequest authenticationMockRequest;
    private Request userInfoMockRequest;
    private ProfileRequest profileRequest;

    @Before
    public void setUp() {
        userInfoMockRequest = mock(Request.class);
        authenticationMockRequest = mock(AuthenticationRequest.class);
        profileRequest = new ProfileRequest(authenticationMockRequest, userInfoMockRequest);
    }

    @Test
    public void shouldAddParameters() {
        final Map params = mock(Map.class);
        final ProfileRequest req = profileRequest.addParameters(params);
        verify(authenticationMockRequest).addParameters(params);
        assertThat(req, is(notNullValue()));
        assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldAddParameter() {
        final ProfileRequest req = profileRequest.addParameter("param", "val");
        verify(authenticationMockRequest).addParameter("param", "val");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldAddHeader() {
        final ProfileRequest req = profileRequest.addHeader("auth", "val123");
        verify(authenticationMockRequest).addHeader(eq("auth"), eq("val123"));
        assertThat(req, is(notNullValue()));
        assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldSetScope() {
        final ProfileRequest req = profileRequest.setScope("oauth2 offline_access profile");
        verify(authenticationMockRequest).setScope("oauth2 offline_access profile");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldSetConnection() {
        final ProfileRequest req = profileRequest.setConnection("my-connection");
        verify(authenticationMockRequest).setConnection("my-connection");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldReturnAuthenticationAfterStartingTheRequest() {
        final UserProfile userProfile = mock(UserProfile.class);
        final Credentials credentials = mock(Credentials.class);

        final AuthenticationRequestMock authenticationRequestMock = new AuthenticationRequestMock(credentials, null);
        final RequestMock tokenInfoRequestMock = new RequestMock(userProfile, null);
        final Callback callback = mock(Callback.class);

        profileRequest = new ProfileRequest(authenticationRequestMock, tokenInfoRequestMock);
        profileRequest.start(callback);

        assertTrue(authenticationRequestMock.isStarted());
        assertTrue(tokenInfoRequestMock.isStarted());

        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
        verify(callback).onSuccess(authenticationCaptor.capture());

        assertThat(authenticationCaptor.getValue(), is(notNullValue()));
        assertThat(authenticationCaptor.getValue(), is(instanceOf(Authentication.class)));
        assertThat(authenticationCaptor.getValue().getCredentials(), is(notNullValue()));
        assertThat(authenticationCaptor.getValue().getCredentials(), is(credentials));
        assertThat(authenticationCaptor.getValue().getProfile(), is(notNullValue()));
        assertThat(authenticationCaptor.getValue().getProfile(), is(userProfile));
    }

    @Test
    public void shouldReturnErrorAfterStartingTheRequestIfAuthenticationRequestFails() {
        final UserProfile userProfile = mock(UserProfile.class);
        final AuthenticationException error = mock(AuthenticationException.class);

        final AuthenticationRequestMock authenticationRequestMock = new AuthenticationRequestMock(null, error);
        final RequestMock tokenInfoRequestMock = new RequestMock(userProfile, null);
        final Callback callback = mock(Callback.class);

        profileRequest = new ProfileRequest(authenticationRequestMock, tokenInfoRequestMock);
        profileRequest.start(callback);

        assertTrue(authenticationRequestMock.isStarted());
        assertFalse(tokenInfoRequestMock.isStarted());

        verify(callback).onFailure(error);
    }

    @Test
    public void shouldReturnErrorAfterStartingTheRequestIfTokenInfoRequestFails() {
        final Credentials credentials = mock(Credentials.class);
        final AuthenticationException error = mock(AuthenticationException.class);

        final AuthenticationRequestMock authenticationRequestMock = new AuthenticationRequestMock(credentials, null);
        final RequestMock tokenInfoRequestMock = new RequestMock(null, error);
        final Callback callback = mock(Callback.class);

        profileRequest = new ProfileRequest(authenticationRequestMock, tokenInfoRequestMock);
        profileRequest.start(callback);

        assertTrue(authenticationRequestMock.isStarted());
        assertTrue(tokenInfoRequestMock.isStarted());

        verify(callback).onFailure(error);
    }

    @Test
    public void shouldExecuteTheRequest() {
        final Credentials credentials = mock(Credentials.class);
        when(authenticationMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                return credentials;
            }
        });
        final UserProfile userProfile = mock(UserProfile.class);
        when(userInfoMockRequest.addParameter(anyString(), anyObject())).thenReturn(userInfoMockRequest);
        when(userInfoMockRequest.addHeader(anyString(), anyString())).thenReturn(userInfoMockRequest);
        when(userInfoMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {
                return userProfile;
            }
        });
        final Authentication executeResult = profileRequest.execute();

        verify(authenticationMockRequest).execute();
        verify(userInfoMockRequest).execute();
        assertThat(executeResult, is(notNullValue()));
        assertThat(executeResult, is(instanceOf(Authentication.class)));
        assertThat(executeResult.getCredentials(), is(notNullValue()));
        assertThat(executeResult.getCredentials(), is(credentials));
        assertThat(executeResult.getProfile(), is(notNullValue()));
        assertThat(executeResult.getProfile(), is(userProfile));
    }

}