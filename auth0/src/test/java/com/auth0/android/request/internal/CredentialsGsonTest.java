package com.auth0.android.request.internal;

import androidx.annotation.NonNull;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;
import com.google.gson.JsonParseException;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.Calendar;
import java.util.Date;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class CredentialsGsonTest extends GsonBaseTest {
    private static final String OPEN_ID_OFFLINE_ACCESS_CREDENTIALS = "src/test/resources/credentials_openid_refresh_token.json";
    private static final String OPEN_ID_CREDENTIALS = "src/test/resources/credentials_openid.json";
    private static final String BASIC_CREDENTIALS = "src/test/resources/credentials.json";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() {
        gson = GsonProvider.buildGson();
    }

    @Test
    public void shouldFailWithInvalidJson() throws Exception {
        expectedException.expect(JsonParseException.class);
        buildCredentialsFrom(json(INVALID));
    }

    @Test
    public void shouldFailWithEmptyJson() throws Exception {
        expectedException.expect(JsonParseException.class);
        buildCredentialsFrom(json(EMPTY_OBJECT));
    }

    @Test
    public void shouldNotRequireAccessToken() throws Exception {
        buildCredentialsFrom(new StringReader("{\"token_type\": \"bearer\"}"));
    }

    @Test
    public void shouldNotRequireTokenType() throws Exception {
        buildCredentialsFrom(new StringReader("{\"access_token\": \"some token\"}"));
    }

    @Test
    public void shouldReturnBasic() throws Exception {
        final Credentials credentials = buildCredentialsFrom(json(BASIC_CREDENTIALS));
        assertThat(credentials, is(notNullValue()));
        assertThat(credentials.getAccessToken(), is(notNullValue()));
        assertThat(credentials.getIdToken(), is(nullValue()));
        assertThat(credentials.getType(), equalTo("bearer"));
        assertThat(credentials.getRefreshToken(), is(nullValue()));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        assertThat(credentials.getExpiresIn().doubleValue(), is(closeTo(86000, 1)));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        assertThat(credentials.getScope(), is(nullValue()));
    }

    @Test
    public void shouldReturnWithExpiresAt() throws Exception {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 1);
        Date exp = cal.getTime();
        String credentialsJSON = generateJSONWithExpiresAt(exp);
        final Credentials credentials = buildCredentialsFrom(new StringReader(credentialsJSON));
        assertThat(credentials, is(notNullValue()));
        assertThat(credentials.getAccessToken(), is(notNullValue()));
        assertThat(credentials.getType(), equalTo("bearer"));
        //The hardcoded value comes from the JSON file
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        double expectedCalculatedExpiresIn = (exp.getTime() - System.currentTimeMillis()) / 1000f;
        assertThat(credentials.getExpiresIn().doubleValue(), is(closeTo(expectedCalculatedExpiresIn, 1)));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        double expiresAt = credentials.getExpiresAt().getTime();
        assertThat(expiresAt, is(closeTo(exp.getTime(), 1)));
    }

    @Test
    public void shouldReturnWithIdToken() throws Exception {
        final Credentials credentials = buildCredentialsFrom(json(OPEN_ID_CREDENTIALS));
        assertThat(credentials, is(notNullValue()));
        assertThat(credentials.getAccessToken(), is(notNullValue()));
        assertThat(credentials.getIdToken(), is(notNullValue()));
        assertThat(credentials.getType(), equalTo("bearer"));
        assertThat(credentials.getRefreshToken(), is(nullValue()));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        assertThat(credentials.getExpiresIn().doubleValue(), is(closeTo(86000, 1)));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        assertThat(credentials.getScope(), is("openid profile"));
    }

    @Test
    public void shouldReturnWithRefreshToken() throws Exception {
        final Credentials credentials = buildCredentialsFrom(json(OPEN_ID_OFFLINE_ACCESS_CREDENTIALS));
        assertThat(credentials, is(notNullValue()));
        assertThat(credentials.getAccessToken(), is(notNullValue()));
        assertThat(credentials.getIdToken(), is(notNullValue()));
        assertThat(credentials.getType(), equalTo("bearer"));
        assertThat(credentials.getRefreshToken(), is(notNullValue()));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        assertThat(credentials.getExpiresIn().doubleValue(), is(closeTo(86000, 1)));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        assertThat(credentials.getScope(), is("openid profile"));
    }

    @Test
    public void shouldSerializeCredentials() {
        Date expiresAt = new Date(CredentialsMock.CURRENT_TIME_MS + 123456 * 1000);
        final String expectedExpiresAt = GsonProvider.formatDate(expiresAt);

        final Credentials expiresInCredentials = new CredentialsMock("id", "access", "ty", "refresh", 123456L);
        final String expiresInJson = gson.toJson(expiresInCredentials);
        assertThat(expiresInJson, containsString("\"id_token\":\"id\""));
        assertThat(expiresInJson, containsString("\"access_token\":\"access\""));
        assertThat(expiresInJson, containsString("\"token_type\":\"ty\""));
        assertThat(expiresInJson, containsString("\"refresh_token\":\"refresh\""));
        assertThat(expiresInJson, containsString("\"expires_in\":123456"));
        assertThat(expiresInJson, containsString("\"expires_at\":\"" + expectedExpiresAt + "\""));
        assertThat(expiresInJson, not(containsString("\"scope\"")));


        final Credentials expiresAtCredentials = new CredentialsMock("id", "access", "ty", "refresh", expiresAt, "openid");
        final String expiresAtJson = gson.toJson(expiresAtCredentials);
        assertThat(expiresAtJson, containsString("\"id_token\":\"id\""));
        assertThat(expiresAtJson, containsString("\"access_token\":\"access\""));
        assertThat(expiresAtJson, containsString("\"token_type\":\"ty\""));
        assertThat(expiresAtJson, containsString("\"refresh_token\":\"refresh\""));
        assertThat(expiresAtJson, containsString("\"expires_in\":123456"));
        assertThat(expiresInJson, containsString("\"expires_at\":\"" + expectedExpiresAt + "\""));
        assertThat(expiresAtJson, containsString("\"scope\":\"openid\""));
    }

    private Credentials buildCredentialsFrom(Reader json) throws IOException {
        return pojoFrom(json, Credentials.class);
    }

    private String generateJSONWithExpiresAt(@NonNull Date expiresAt) {
        return "{\n" +
                "\"access_token\": \"s6GS5FGJN2jfd4l6\",\n" +
                "\"token_type\": \"bearer\",\n" +
                "\"expires_in\": 86000,\n" +
                "\"expires_at\": \"" + GsonProvider.formatDate(expiresAt) + "\"\n" +
                "}";
    }
}
