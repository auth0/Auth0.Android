package com.auth0.android.authentication.request;

import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class DelegationRequestTest {

    private ParameterizableRequest mockRequest;
    private DelegationRequest delegationRequest;

    @Before
    public void setUp() throws Exception {
        mockRequest = mock(ParameterizableRequest.class);
        delegationRequest = new DelegationRequest(mockRequest);
    }

    @Test
    public void shouldAddAllTheParameters() throws Exception {
        final Map params = mock(Map.class);
        delegationRequest.addParameters(params);
        verify(mockRequest).addParameters(params);
    }

    @Test
    public void shouldSetApiType() throws Exception {
        delegationRequest.setApiType("type-auth0");
        verify(mockRequest).addParameter("api_type", "type-auth0");
    }

    @Test
    public void shouldSetScope() throws Exception {
        delegationRequest.setScope("oauth2 offline_access profile");
        verify(mockRequest).addParameter("scope", "oauth2 offline_access profile");
    }

    @Test
    public void shouldSetTarget() throws Exception {
        delegationRequest.setTarget("target-is");
        verify(mockRequest).addParameter("target", "target-is");
    }

    @Test
    public void shouldStartTheRequest() throws Exception {
        final BaseCallback callback = mock(BaseCallback.class);
        delegationRequest.start(callback);
        verify(mockRequest).start(callback);
    }

    @Test
    public void shouldExecuteTheRequest() throws Exception {
        delegationRequest.execute();
        verify(mockRequest).execute();
    }

}