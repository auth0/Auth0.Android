package com.auth0.android.request.internal;

import com.auth0.android.result.Credentials;
import com.google.gson.JsonParseException;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class CredentialsGsonTest extends GsonBaseTest {
    private static final String OPEN_ID_OFFLINE_ACCESS_CREDENTIALS = "src/test/resources/credentials_openid_refresh_token.json";
    private static final String OPEN_ID_CREDENTIALS = "src/test/resources/credentials_openid.json";
    private static final String BASIC_CREDENTIALS = "src/test/resources/credentials.json";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
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
        assertThat(credentials.getExpiresIn(), is(86000L));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        assertThat(credentials.getScope(), is(nullValue()));
    }

    @Test
    public void shouldReturnWithIdToken() throws Exception {
        final Credentials credentials = buildCredentialsFrom(json(OPEN_ID_CREDENTIALS));
        assertThat(credentials, is(notNullValue()));
        assertThat(credentials.getAccessToken(), is(notNullValue()));
        assertThat(credentials.getIdToken(), is(notNullValue()));
        assertThat(credentials.getType(), equalTo("bearer"));
        assertThat(credentials.getRefreshToken(), is(nullValue()));
        assertThat(credentials.getExpiresIn(), is(86000L));
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
        assertThat(credentials.getExpiresIn(), is(86000L));
        assertThat(credentials.getExpiresAt(), is(notNullValue()));
        assertThat(credentials.getScope(), is("openid profile"));
    }

    private Credentials buildCredentialsFrom(Reader json) throws IOException {
        return pojoFrom(json, Credentials.class);
    }

}
