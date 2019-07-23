package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.management.ManagementException;

import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.any;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class ManagementErrorBuilderTest {

    private ManagementErrorBuilder builder;

    @Before
    public void setUp() {
        builder = new ManagementErrorBuilder();
    }

    @Test
    public void shouldCreateFromMessage() {
        final ManagementException ex = builder.from("message");

        assertThat(ex.getCause(), is(nullValue()));
        assertThat(ex.getCode(), is("a0.sdk.internal_error.unknown"));
        assertThat(ex.getStatusCode(), is(0));
        assertThat(ex.getDescription(), is(any(String.class)));
    }

    @Test
    public void shouldCreateFromMessageAndException() {
        final Auth0Exception auth0Ex = Mockito.mock(Auth0Exception.class);
        final ManagementException ex = builder.from("message", auth0Ex);

        assertThat(ex.getCause(), CoreMatchers.<Throwable>equalTo(auth0Ex));
        assertThat(ex.getCode(), is("a0.sdk.internal_error.unknown"));
        assertThat(ex.getStatusCode(), is(0));
        assertThat(ex.getDescription(), is(any(String.class)));
    }

    @Test
    public void shouldCreateFromStringPayloadAndIntCode() {
        final ManagementException ex = builder.from("message", 999);

        assertThat(ex.getCause(), is(nullValue()));
        assertThat(ex.getCode(), is("a0.sdk.internal_error.plain"));
        assertThat(ex.getStatusCode(), is(999));
        assertThat(ex.getDescription(), is("message"));
    }

    @Test
    public void shouldCreateFromMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("key", "value");
        map.put("asd", "123");
        final ManagementException ex = builder.from(map);

        assertThat(ex.getCause(), is(nullValue()));
        assertThat(ex.getCode(), is("a0.sdk.internal_error.unknown"));
        assertThat(ex.getStatusCode(), is(0));
        assertThat(ex.getDescription(), is(any(String.class)));
        assertThat(ex.getValue("key"), CoreMatchers.<Object>is("value"));
        assertThat(ex.getValue("asd"), CoreMatchers.<Object>is("123"));
    }
}