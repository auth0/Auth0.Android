package com.auth0.android.authentication.request;

import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Map;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21, manifest = Config.NONE)
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
        final DatabaseConnectionRequest req = dbRequest.addParameters(params);
        verify(mockRequest).addParameters(params);
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(dbRequest));
    }

    @Test
    public void shouldAddParameter() throws Exception {
        final DatabaseConnectionRequest req = dbRequest.addParameter("key", "value");
        verify(mockRequest).addParameter("key", "value");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(dbRequest));
    }

    @Test
    public void shouldAddHeader() throws Exception {
        final DatabaseConnectionRequest req = dbRequest.addHeader("header", "value");
        verify(mockRequest).addHeader("header", "value");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(dbRequest));
    }

    @Test
    public void shouldSetConnection() throws Exception {
        final DatabaseConnectionRequest req = dbRequest.setConnection("my-connection");
        verify(mockRequest).addParameter("connection", "my-connection");
        Assert.assertThat(req, is(notNullValue()));
        Assert.assertThat(req, is(dbRequest));
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