package com.auth0.android.request.internal;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.junit.Test;

import java.io.FileReader;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

public class CredentialsDeserializerTest {

    private static final String OPEN_ID_OFFLINE_ACCESS_CREDENTIALS = "src/test/resources/credentials_openid_refresh_token.json";

    private static final long CURRENT_TIME_MS = 1234567890000L;

    @Test
    public void shouldSetExpiresAtFromExpiresIn() throws Exception {
        final CredentialsDeserializer deserializer = new CredentialsDeserializer();
        final CredentialsDeserializer spy = spy(deserializer);
        doReturn(CredentialsMock.CURRENT_TIME_MS).when(spy).getCurrentTimeInMillis();

        final Gson gson = new GsonBuilder()
                .registerTypeAdapter(Credentials.class, spy)
                .create();

        final Credentials credentials = gson.getAdapter(Credentials.class).fromJson(new FileReader(OPEN_ID_OFFLINE_ACCESS_CREDENTIALS));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        assertThat(credentials.getExpiresAt().getTime(), is(CURRENT_TIME_MS + 86000 * 1000));
    }
}