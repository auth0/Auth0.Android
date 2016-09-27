package com.auth0.android.authentication.request;

import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class DatabaseConnectionRequestTest {

    private ParameterizableRequest mockRequest;
    private DatabaseConnectionRequest dbRequest;

    @Before
    public void setUp() throws Exception {
        mockRequest = mock(ParameterizableRequest.class);
        dbRequest = new DatabaseConnectionRequest<>(mockRequest);
    }

    @Test
    public void shouldAddAllTheParameters() throws Exception {
        final Map params = mock(Map.class);
        dbRequest.addParameters(params);
        verify(mockRequest).addParameters(params);
    }

    @Test
    public void shouldAddParameter() throws Exception {
        dbRequest.addParameter("key", "value");
        verify(mockRequest).addParameter("key", "value");
    }

    @Test
    public void shouldAddHeader() throws Exception {
        dbRequest.addHeader("header", "value");
        verify(mockRequest).addHeader("header", "value");
    }

    @Test
    public void shouldSetConnection() throws Exception {
        dbRequest.setConnection("my-connection");
        verify(mockRequest).addParameter("connection", "my-connection");
    }

    @Test
    public void shouldStartTheRequest() throws Exception {
        final BaseCallback callback = mock(BaseCallback.class);
        dbRequest.start(callback);
        verify(mockRequest).start(callback);
    }

    @Test
    public void shouldExecuteTheRequest() throws Exception {
        dbRequest.execute();
        verify(mockRequest).execute();
    }

}