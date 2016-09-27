package com.auth0.android.authentication.request;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.ParameterizableRequest;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class ProfileRequestTest {

    private AuthenticationRequest credentialsMockRequest;
    private ParameterizableRequest tokenInfoMockRequest;
    private ProfileRequest profileRequest;

    @Before
    public void setUp() throws Exception {
        credentialsMockRequest = mock(AuthenticationRequest.class);
        tokenInfoMockRequest = mock(ParameterizableRequest.class);
        profileRequest = new ProfileRequest(credentialsMockRequest, tokenInfoMockRequest);
    }

    @Test
    public void shouldAddParameters() throws Exception {
        final Map params = mock(Map.class);
        profileRequest.addParameters(params);
        verify(credentialsMockRequest).addAuthenticationParameters(params);
    }

    @Test
    public void shouldSetScope() throws Exception {
        profileRequest.setScope("oauth2 offline_access profile");
        verify(credentialsMockRequest).setScope("oauth2 offline_access profile");
    }

    @Test
    public void shouldSetConnection() throws Exception {
        profileRequest.setConnection("my-connection");
        verify(credentialsMockRequest).setConnection("my-connection");
    }

    @Test
    public void shouldReturnAuthenticationAfterStartingTheRequest() throws Exception {
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
    public void shouldReturnErrorAfterStartingTheRequestIfAuthenticationRequestFails() throws Exception {
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
    public void shouldReturnErrorAfterStartingTheRequestIfTokenInfoRequestFails() throws Exception {
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
    public void shouldExecuteTheRequest() throws Exception {
        final Credentials credentials = mock(Credentials.class);
        when(credentialsMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return credentials;
            }
        });
        final UserProfile userProfile = mock(UserProfile.class);
        when(tokenInfoMockRequest.addParameter(anyString(), anyObject())).thenReturn(tokenInfoMockRequest);
        when(tokenInfoMockRequest.execute()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return userProfile;
            }
        });
        final Authentication executeResult = profileRequest.execute();

        verify(credentialsMockRequest).execute();
        verify(tokenInfoMockRequest).execute();
        assertThat(executeResult, is(notNullValue()));
        assertThat(executeResult, is(instanceOf(Authentication.class)));
        assertThat(executeResult.getCredentials(), is(notNullValue()));
        assertThat(executeResult.getCredentials(), is(credentials));
        assertThat(executeResult.getProfile(), is(notNullValue()));
        assertThat(executeResult.getProfile(), is(userProfile));
    }

}