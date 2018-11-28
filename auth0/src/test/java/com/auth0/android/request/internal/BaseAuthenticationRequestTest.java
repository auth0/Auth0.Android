package com.auth0.android.request.internal;

import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.result.Credentials;
import com.auth0.android.util.AuthenticationAPI;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.mockwebserver.RecordedRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.junit.Assert.assertThat;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21, manifest = Config.NONE)
public class BaseAuthenticationRequestTest {

    public static final String OAUTH_PATH = "oauth";
    public static final String RESOURCE_OWNER_PATH = "ro";
    public static final String TOKEN_PATH = "token";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private AuthenticationAPI mockAPI;
    private BaseAuthenticationRequest request;
    private Gson gson;

    @Before
    public void setUp() throws Exception {
        mockAPI = new AuthenticationAPI();
        gson = GsonProvider.buildGson();
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(RESOURCE_OWNER_PATH)
                .build();
        request = createRequest(url);
    }

    @After
    public void tearDown() throws Exception {
        mockAPI.shutdown();
    }

    private BaseAuthenticationRequest createRequest(HttpUrl url) {
        return new BaseAuthenticationRequest(url, new OkHttpClient(), gson, "POST", Credentials.class);
    }

    private Map<String, String> bodyFromRequest(RecordedRequest request) throws java.io.IOException {
        final Type mapType = new TypeToken<Map<String, String>>() {
        }.getType();
        return gson.fromJson(request.getBody().readUtf8(), mapType);
    }

    @Test
    public void shouldSetGrantType() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        request.setGrantType("grantType")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("grant_type", "grantType"));
    }

    @Test
    public void shouldSetConnection() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        request.setConnection("my-connection")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("connection", "my-connection"));
    }

    @Test
    public void shouldNotSetConnectionOnNonLegacyEndpoints() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("method POST must have a request body.");
        //no body was sent

        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(TOKEN_PATH)
                .build();
        AuthenticationRequest req = createRequest(url);
        req.setConnection("my-connection")
                .execute();
    }

    @Test
    public void shouldSetRealm() throws Exception {
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(TOKEN_PATH)
                .build();
        AuthenticationRequest req = createRequest(url);
        mockAPI.willReturnSuccessfulLogin();
        req.setRealm("users")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("realm", "users"));
    }

    @Test
    public void shouldNotSetRealmOnLegacyEndpoints() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("method POST must have a request body.");
        //no body was sent

        request.setRealm("users")
                .execute();
    }

    @Test
    public void shouldSetScope() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        request.setScope("profile photos")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("scope", "profile photos"));
    }

    @Test
    public void shouldSetDevice() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        request.setDevice("nexus-5x")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("device", "nexus-5x"));
    }

    @Test
    public void shouldSetAudience() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        request.setAudience("https://domain.auth0.com")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("audience", "https://domain.auth0.com"));
    }

    @Test
    public void shouldSetAccessToken() throws Exception {
        mockAPI.willReturnSuccessfulLogin();
        request.setAccessToken("accessToken")
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("access_token", "accessToken"));
    }

    @Test
    public void shouldAddAuthenticationParameters() throws Exception {
        HashMap<String, Object> parameters = new HashMap<>();
        parameters.put("extra", "value");
        parameters.put("123", "890");
        mockAPI.willReturnSuccessfulLogin();
        request.addAuthenticationParameters(parameters)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("extra", "value"));
        assertThat(body, hasEntry("123", "890"));
    }

    @Test
    public void shouldWhiteListOAuth2ParametersOnLegacyEndpoints() throws Exception {
        HashMap<String, Object> parameters = new HashMap<>();
        parameters.put("extra", "value");
        parameters.put("realm", "users");
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(RESOURCE_OWNER_PATH)
                .build();
        AuthenticationRequest req = createRequest(url);
        mockAPI.willReturnSuccessfulLogin();
        req.addAuthenticationParameters(parameters)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("extra", "value"));
        assertThat(body, not(hasKey("realm")));
    }

    @Test
    public void shouldWhiteListLegacyParametersOnNonLegacyEndpoints() throws Exception {
        HashMap<String, Object> parameters = new HashMap<>();
        parameters.put("extra", "value");
        parameters.put("connection", "my-connection");
        HttpUrl url = HttpUrl.parse(mockAPI.getDomain())
                .newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(TOKEN_PATH)
                .build();
        AuthenticationRequest req = createRequest(url);
        mockAPI.willReturnSuccessfulLogin();
        req.addAuthenticationParameters(parameters)
                .execute();

        final RecordedRequest request = mockAPI.takeRequest();
        Map<String, String> body = bodyFromRequest(request);
        assertThat(body, hasEntry("extra", "value"));
        assertThat(body, not(hasKey("connection")));
    }

}