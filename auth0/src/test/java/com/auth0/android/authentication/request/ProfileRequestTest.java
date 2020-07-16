package com.auth0.android.authentication.request;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthRequest;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.result.Authentication;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.UserProfile;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Map;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class ProfileRequestTest {

    private AuthRequest authenticationMockRequest;
    private ParameterizableRequest userInfoMockRequest;
    private ProfileRequest profileRequest;

    @Before
    public void setUp() {
        userInfoMockRequest = mock(ParameterizableRequest.class);
        authenticationMockRequest = mock(AuthRequest.class);
        profileRequest = new ProfileRequest(authenticationMockRequest, userInfoMockRequest);
    }

    @Test
    public void shouldAddParameters() {
        final Map params = mock(Map.class);
        final ProfileRequest req = profileRequest.addParameters(params);
        verify(authenticationMockRequest).addAuthenticationParameters(params);
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldAddHeader() {
        final ProfileRequest req = profileRequest.addHeader("auth", "val123");
        verify(authenticationMockRequest).addHeader(eq("auth"), eq("val123"));
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldNotAddHeaderWithAuthenticationRequest() {
        AuthenticationRequest authenticationMockRequest = mock(AuthenticationRequest.class);
        ProfileRequest profileRequest = new ProfileRequest(authenticationMockRequest, userInfoMockRequest);
        final ProfileRequest req = profileRequest.addHeader("auth", "val123");
        verifyZeroInteractions(authenticationMockRequest);
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldSetScope() {
        final ProfileRequest req = profileRequest.setScope("oauth2 offline_access profile");
        verify(authenticationMockRequest).setScope("oauth2 offline_access profile");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldSetConnection() {
        final ProfileRequest req = profileRequest.setConnection("my-connection");
        verify(authenticationMockRequest).setConnection("my-connection");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(profileRequest));
    }

    @Test
    public void shouldReturnAuthenticationAfterStartingTheRequest() {
        final UserProfile userProfile = mock(UserProfile.class);
        final Credentials credentials = mock(Credentials.class);

        final AuthenticationRequestMock authenticationRequestMock = new AuthenticationRequestMock(credentials, null);
        final ParameterizableRequestMock tokenInfoRequestMock = new ParameterizableRequestMock(userProfile, null);
        final BaseCallback callback = mock(BaseCallback.class);

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
        final ParameterizableRequestMock tokenInfoRequestMock = new ParameterizableRequestMock(userProfile, null);
        final BaseCallback callback = mock(BaseCallback.class);

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
        final ParameterizableRequestMock tokenInfoRequestMock = new ParameterizableRequestMock(null, error);
        final BaseCallback callback = mock(BaseCallback.class);

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