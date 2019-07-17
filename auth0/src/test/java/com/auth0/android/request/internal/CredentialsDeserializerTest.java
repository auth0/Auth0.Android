package com.auth0.android.request.internal;

import android.support.annotation.NonNull;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import java.io.FileReader;
import java.util.Calendar;
import java.util.Date;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class CredentialsDeserializerTest {

    private static final String BASIC_CREDENTIALS = "src/test/resources/credentials.json";

    private Gson gson;

    @Before
    public void setUp() {
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
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 7);
        Date expiresAt = cal.getTime();
        final Credentials credentials = gson.getAdapter(Credentials.class).fromJson(generateExpiresAtCredentialsJSON(expiresAt));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        //The hardcoded value comes from the JSON file
        assertThat(credentials.getExpiresAt().getTime(), is(expiresAt.getTime()));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        assertThat(credentials.getExpiresIn(), Matchers.is((expiresAt.getTime() - CredentialsMock.CURRENT_TIME_MS) / 1000));
    }


    private String generateExpiresAtCredentialsJSON(@NonNull Date expiresAt) {
        return "{\n" +
                "\"access_token\": \"s6GS5FGJN2jfd4l6\",\n" +
                "\"token_type\": \"bearer\",\n" +
                "\"expires_in\": 86000,\n" +
                "\"expires_at\": \"" + GsonProvider.formatDate(expiresAt) + "\"\n" +
                "}";
    }

}