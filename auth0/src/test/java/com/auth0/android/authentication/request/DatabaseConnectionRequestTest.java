package com.auth0.android.authentication.request;

import com.auth0.android.callback.Callback;
import com.auth0.android.request.Request;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.Map;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
public class DatabaseConnectionRequestTest {

    private Request mockRequest;
    private DatabaseConnectionRequest dbRequest;

    @Before
    public void setUp() {
        mockRequest = mock(Request.class);
        dbRequest = new DatabaseConnectionRequest<>(mockRequest);
    }

    @Test
    public void shouldAddAllTheParameters() {
        final Map params = mock(Map.class);
        final DatabaseConnectionRequest req = dbRequest.addParameters(params);
        verify(mockRequest).addParameters(params);
        assertThat(req, is(notNullValue()));
        assertThat(req, is(dbRequest));
    }

    @Test
    public void shouldAddParameter() {
        final DatabaseConnectionRequest req = dbRequest.addParameter("key", "value");
        verify(mockRequest).addParameter("key", "value");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(dbRequest));
    }

    @Test
    public void shouldAddHeader() {
        final DatabaseConnectionRequest req = dbRequest.addHeader("header", "value");
        verify(mockRequest).addHeader("header", "value");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(dbRequest));
    }

    @Test
    public void shouldSetConnection() {
        final DatabaseConnectionRequest req = dbRequest.setConnection("my-connection");
        verify(mockRequest).addParameter("connection", "my-connection");
        assertThat(req, is(notNullValue()));
        assertThat(req, is(dbRequest));
    }

    @Test
    public void shouldStartTheRequest() {
        final Callback callback = mock(Callback.class);
        dbRequest.start(callback);
        verify(mockRequest).start(callback);
    }

    @Test
    public void shouldExecuteTheRequest() {
        dbRequest.execute();
        verify(mockRequest).execute();
    }

}