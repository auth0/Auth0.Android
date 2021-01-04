package com.auth0.android.management;

import com.auth0.android.NetworkErrorException;

import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class ManagementExceptionTest {

    @Test
    public void shouldNotHaveNetworkError() {
        ManagementException ex = new ManagementException("Something else happened");
        assertThat(ex.isNetworkError(), is(false));
    }

    @Test
    public void shouldHaveNetworkError() {
        ManagementException ex = new ManagementException("Request has definitely failed", new NetworkErrorException(new IOException()));
        assertThat(ex.isNetworkError(), is(true));
    }
}