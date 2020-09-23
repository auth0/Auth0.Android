package com.auth0.android.request.internal;

import android.support.annotation.NonNull;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.junit.Before;
import org.junit.Test;

import java.io.FileReader;
import java.util.Calendar;
import java.util.Date;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.core.Is.is;

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
        assertThat(credentials.getExpiresIn().doubleValue(), is(closeTo(86000, 1)));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        double expiresAt = credentials.getExpiresAt().getTime();
        double expectedExpiresAt = CredentialsMock.CURRENT_TIME_MS + 86000 * 1000;
        assertThat(expiresAt, is(closeTo(expectedExpiresAt, 1)));
    }

    @Test
    public void shouldSetExpiresInFromExpiresAt() throws Exception {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 7);
        Date exp = cal.getTime();
        final Credentials credentials = gson.getAdapter(Credentials.class).fromJson(generateExpiresAtCredentialsJSON(exp));
        //The hardcoded value comes from the JSON file
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        double expiresAt = credentials.getExpiresAt().getTime();
        double expectedExpiresAt = exp.getTime();
        assertThat(expiresAt, is(closeTo(expectedExpiresAt, 1)));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        double expectedExpiresIn = (exp.getTime() - CredentialsMock.CURRENT_TIME_MS) / 1000f;
        assertThat(credentials.getExpiresIn().doubleValue(), is(closeTo(expectedExpiresIn, 1)));
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