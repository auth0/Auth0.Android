package com.auth0.android.request.internal;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.Request;
import com.auth0.android.request.kt.ErrorAdapter;
import com.auth0.android.request.kt.HttpMethod;
import com.auth0.android.request.kt.JsonAdapter;
import com.auth0.android.request.kt.NetworkingClient;
import com.auth0.android.request.kt.RequestOptions;
import com.auth0.android.result.Credentials;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.hamcrest.collection.IsMapWithSize.aMapWithSize;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@RunWith(RobolectricTestRunner.class)
public class BaseAuthenticationRequestTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private static final String BASE_URL = "https://auth0.com/oauth/token";

    @Mock
    private NetworkingClient client;
    @Mock
    private JsonAdapter<Credentials> resultAdapter;
    @Mock
    private ErrorAdapter<AuthenticationException> errorAdapter;
    @Captor
    private ArgumentCaptor<RequestOptions> optionsCaptor;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    private AuthenticationRequest createRequest(String url) {
        Request<Credentials, AuthenticationException> baseRequest = new BaseRequest<>(HttpMethod.POST.INSTANCE, url, client, resultAdapter, errorAdapter);
        AuthenticationRequest request = new BaseAuthenticationRequest(baseRequest);
        return spy(request);
    }

    @Test
    public void shouldSetGrantType() throws Exception {
        createRequest(BASE_URL)
                .setGrantType("grantType")
                .execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("grant_type", "grantType"));
    }

    @Test
    public void shouldSetConnection() throws Exception {
        createRequest(BASE_URL)
                .setConnection("my-connection")
                .execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("connection", "my-connection"));
    }

    @Test
    public void shouldSetRealm() throws Exception {
        createRequest(BASE_URL)
                .setRealm("my-realm")
                .execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("realm", "my-realm"));
    }

    @Test
    public void shouldSetScope() throws Exception {
        createRequest(BASE_URL)
                .setScope("email profile")
                .execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("scope", "email profile"));
    }

    @Test
    public void shouldSetDevice() throws Exception {
        //TODO: This was once used to identify the device authenticating. No longer used.
        createRequest(BASE_URL)
                .setDevice("android-phone")
                .execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("device", "email profile"));
    }

    @Test
    public void shouldSetAudience() throws Exception {
        createRequest(BASE_URL)
                .setAudience("my-api")
                .execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(1));
        assertThat(values, hasEntry("audience", "my-api"));
    }

    @Test
    public void shouldAddAuthenticationParameters() throws Exception {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("extra", "value");
        parameters.put("123", "890");

        createRequest(BASE_URL)
                .addParameters(parameters)
                .execute();

        verify(client).load(eq(BASE_URL), optionsCaptor.capture());
        Map<String, String> values = optionsCaptor.getValue().getParameters();
        assertThat(values, aMapWithSize(2));
        assertThat(values, hasEntry("extra", "value"));
        assertThat(values, hasEntry("123", "890"));
    }
}