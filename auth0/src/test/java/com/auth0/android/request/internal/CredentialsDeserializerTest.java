package com.auth0.android.request.internal;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import java.io.FileReader;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class CredentialsDeserializerTest {

    private static final String BASIC_CREDENTIALS = "src/test/resources/credentials.json";
    private static final String EXPIRES_AT_CREDENTIALS = "src/test/resources/credentials_expires_at.json";

    private Gson gson;

    @Before
    public void setUp() throws Exception {
        final CredentialsDeserializerMock deserializer = new CredentialsDeserializerMock();
        gson = new GsonBuilder()
                .setDateFormat(GsonProvider.DATE_FORMAT)
                .registerTypeAdapter(Credentials.class, deserializer)
                .create();
    }

    @Test
    public void shouldSetExpiresAtFromExpiresIn() throws Exception {
        final Credentials credentials = gson.getAdapter(Credentials.class).fromJson(new FileReader(BASIC_CREDENTIALS));
        assertThat(credentials.getExpiresIn(), is(86000L));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        assertThat(credentials.getExpiresAt().getTime(), is(CredentialsMock.CURRENT_TIME_MS + 86000 * 1000));
    }

    @Test
    public void shouldSetExpiresInFromExpiresAt() throws Exception {
        final Credentials credentials = gson.getAdapter(Credentials.class).fromJson(new FileReader(EXPIRES_AT_CREDENTIALS));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        //The hardcoded value comes from the JSON file
        assertThat(credentials.getExpiresAt().getTime(), is(1234691346555L));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        assertThat(credentials.getExpiresIn(), Matchers.is((1234691346555L - CredentialsMock.CURRENT_TIME_MS) / 1000));
    }

}