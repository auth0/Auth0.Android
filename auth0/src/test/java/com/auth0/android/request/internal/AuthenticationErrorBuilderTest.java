package com.auth0.android.request.internal;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;

import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.any;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class AuthenticationErrorBuilderTest {

    private AuthenticationErrorBuilder builder;

    @Before
    public void setUp() {
        builder = new AuthenticationErrorBuilder();
    }

    @Test
    public void shouldCreateFromMessage() {
        final AuthenticationException ex = builder.from("message");

        assertThat(ex.getCause(), is(nullValue()));
        assertThat(ex.getCode(), is("a0.sdk.internal_error.unknown"));
        assertThat(ex.getStatusCode(), is(0));
        assertThat(ex.getDescription(), is(any(String.class)));
    }

    @Test
    public void shouldCreateFromMessageAndException() {
        final Auth0Exception auth0Ex = Mockito.mock(Auth0Exception.class);
        final AuthenticationException ex = builder.from("message", auth0Ex);

        assertThat(ex.getCause(), CoreMatchers.<Throwable>equalTo(auth0Ex));
        assertThat(ex.getCode(), is("a0.sdk.internal_error.unknown"));
        assertThat(ex.getStatusCode(), is(0));
        assertThat(ex.getDescription(), is(any(String.class)));
    }

    @Test
    public void shouldCreateFromStringPayloadAndIntCode() {
        final AuthenticationException ex = builder.from("message", 999);

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
        final AuthenticationException ex = builder.from(map);

        assertThat(ex.getCause(), is(nullValue()));
        assertThat(ex.getCode(), is("a0.sdk.internal_error.unknown"));
        assertThat(ex.getStatusCode(), is(0));
        assertThat(ex.getDescription(), is(any(String.class)));
        assertThat(ex.getValue("key"), CoreMatchers.<Object>is("value"));
        assertThat(ex.getValue("asd"), CoreMatchers.<Object>is("123"));
    }
}