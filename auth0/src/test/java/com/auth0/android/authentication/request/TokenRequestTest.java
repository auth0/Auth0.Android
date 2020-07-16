package com.auth0.android.authentication.request;

import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class TokenRequestTest {

    private ParameterizableRequest mockRequest;
    private TokenRequest tokenRequest;

    @Before
    public void setUp() {
        mockRequest = mock(ParameterizableRequest.class);
        tokenRequest = new TokenRequest(mockRequest);
    }

    @Test
    public void shouldSetCodeVerifier() {
        final TokenRequest req = tokenRequest.setCodeVerifier("1234567890");
        verify(mockRequest).addParameter("code_verifier", "1234567890");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(tokenRequest));
    }

    @Test
    public void shouldStartTheRequest() {
        final BaseCallback callback = mock(BaseCallback.class);
        tokenRequest.start(callback);
        verify(mockRequest).start(callback);
    }

    @Test
    public void shouldExecuteTheRequest() {
        tokenRequest.execute();
        verify(mockRequest).execute();
    }

    @Test
    public void shouldAddHeaders() {
        tokenRequest.addHeader("auth", "val123");
        verify(mockRequest).addHeader(eq("auth"), eq("val123"));
    }

    @Test
    public void shouldAddParameters() {
        Map params = mock(Map.class);
        tokenRequest.addParameters(params);
        verify(mockRequest).addParameters(eq(params));
    }

}