package com.auth0.android.request.internal;


import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import okhttp3.ResponseBody;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class ResponseUtilsTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldCloseBody() throws Exception {
        ResponseBody body = mock(ResponseBody.class);
        ResponseUtils.closeStream(body);

        verify(body).close();
    }
}