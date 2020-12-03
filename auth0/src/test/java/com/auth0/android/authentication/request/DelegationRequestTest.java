package com.auth0.android.authentication.request;

import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.Request;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.Map;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
public class DelegationRequestTest {

    private Request mockRequest;
    private DelegationRequest delegationRequest;

    @Before
    public void setUp() {
        mockRequest = mock(Request.class);
        delegationRequest = new DelegationRequest(mockRequest);
    }

    @Test
    public void shouldAddAllTheParameters() {
        final Map params = mock(Map.class);
        final DelegationRequest req = delegationRequest.addParameters(params);
        verify(mockRequest).addParameters(params);
        assertThat(req, is(notNullValue()));
        assertThat(req, is(delegationRequest));
    }

    @Test
    public void shouldAddParameter() {
        final DelegationRequest req = delegationRequest.addParameter("param", "val");
        verify(mockRequest).addParameter("param", "val");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(delegationRequest));
    }

    @Test
    public void shouldAddHeader() {
        final DelegationRequest req = delegationRequest.addHeader("auth", "val123");
        verify(mockRequest).addHeader(eq("auth"), eq("val123"));
        assertThat(req, is(Matchers.notNullValue()));
        assertThat(req, is(delegationRequest));
    }

    @Test
    public void shouldSetApiType() {
        final DelegationRequest req = delegationRequest.setApiType("type-auth0");
        verify(mockRequest).addParameter("api_type", "type-auth0");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(delegationRequest));
    }

    @Test
    public void shouldSetScope() {
        final DelegationRequest req = delegationRequest.setScope("oauth2 offline_access profile");
        verify(mockRequest).addParameter("scope", "oauth2 offline_access profile");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(delegationRequest));
    }

    @Test
    public void shouldSetTarget() {
        final DelegationRequest req = delegationRequest.setTarget("target-is");
        verify(mockRequest).addParameter("target", "target-is");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(delegationRequest));
    }

    @Test
    public void shouldStartTheRequest() {
        final BaseCallback callback = mock(BaseCallback.class);
        delegationRequest.start(callback);
        verify(mockRequest).start(callback);
    }

    @Test
    public void shouldExecuteTheRequest() {
        delegationRequest.execute();
        verify(mockRequest).execute();
    }

}