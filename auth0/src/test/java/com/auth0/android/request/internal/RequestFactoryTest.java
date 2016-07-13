package com.auth0.android.request.internal;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;
import com.auth0.android.request.ErrorBuilder;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import org.hamcrest.core.Is;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Map;

import static com.auth0.android.request.internal.HeaderMatcher.hasAuthorizationHeader;
import static com.auth0.android.request.internal.HeaderMatcher.hasClientInfoHeader;
import static com.auth0.android.request.internal.HeaderMatcher.hasNoAuthorizationHeader;
import static com.auth0.android.request.internal.HeaderMatcher.hasUserAgentHeader;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class RequestFactoryTest {

    private static final String METHOD_POST = "POST";
    private static final String METHOD_PATCH = "PATCH";
    private static final String METHOD_DELETE = "DELETE";
    public static final String CLIENT_INFO = "client_info";
    public static final String USER_AGENT = "user_agent";
    public static final String TOKEN = "token";
    public static final String BEARER_PREFIX = "Bearer ";
    private RequestFactory factory;

    @Mock
    private OkHttpClient client;
    private Gson gson;
    @Mock
    private ErrorBuilder<Auth0Exception> builder;
    private HttpUrl url;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        gson = new Gson();
        url = HttpUrl.parse("http://domain.auth0.com");
        factory = createBasicFactory();
    }

    @Test
    public void shouldHaveNonNullHeaders() throws Exception {
        final RequestFactory factory = new RequestFactory();
        assertThat(factory.getHeaders(), is(notNullValue()));
    }

    @Test
    public void shouldHaveClientInfoHeader() throws Exception {
        final RequestFactory factory = new RequestFactory();
        factory.setClientInfo(CLIENT_INFO);
        assertThat(factory.getHeaders().size(), is(1));
        assertThat(factory.getHeaders().get(RequestFactory.CLIENT_INFO_HEADER), is(equalTo(CLIENT_INFO)));
    }

    @Test
    public void shouldHaveUserAgentHeader() throws Exception {
        final RequestFactory factory = new RequestFactory();
        factory.setUserAgent(USER_AGENT);
        assertThat(factory.getHeaders().size(), is(1));
        assertThat(factory.getHeaders().get(RequestFactory.USER_AGENT_HEADER), is(equalTo(USER_AGENT)));
    }

    @Test
    public void shouldHaveAuthorizationHeader() throws Exception {
        final RequestFactory factory = new RequestFactory(TOKEN);
        assertThat(factory.getHeaders().size(), is(1));
        assertThat(factory.getHeaders().get(RequestFactory.AUTHORIZATION_HEADER), is(equalTo(BEARER_PREFIX + TOKEN)));
    }

    @Test
    public void shouldCreateAuthenticationPOSTRequest() throws Exception {
        final MockAuthenticationRequest request = (MockAuthenticationRequest) factory.authenticationPOST(url, client, gson);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasNoAuthorizationHeader());
    }

    @Test
    public void shouldCreateAuthorizedAuthenticationPOSTRequest() throws Exception {
        final MockRequestFactory factory = createAuthorizedFactory();
        final MockAuthenticationRequest request = (MockAuthenticationRequest) factory.authenticationPOST(url, client, gson);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasAuthorizationHeader(TOKEN));
    }

    @Test
    public void shouldCreatePOSTRequestOfTClass() throws Exception {
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.POST(url, client, gson, Auth0.class, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.clazz, Is.<Class<Auth0>>is((Auth0.class)));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasNoAuthorizationHeader());
    }

    @Test
    public void shouldCreateAuthorizedPOSTRequestOfTClass() throws Exception {
        final MockRequestFactory factory = createAuthorizedFactory();
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.POST(url, client, gson, Auth0.class, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.clazz, Is.<Class<Auth0>>is((Auth0.class)));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasAuthorizationHeader(TOKEN));
    }

    @Test
    public void shouldCreatePOSTRequestOfTToken() throws Exception {
        TypeToken<Auth0> typeToken = createTypeToken();
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.POST(url, client, gson, typeToken, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.typeToken, is(typeToken));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasNoAuthorizationHeader());
    }

    @Test
    public void shouldCreateAuthorizedPOSTRequestOfTToken() throws Exception {
        final MockRequestFactory factory = createAuthorizedFactory();
        TypeToken<Auth0> typeToken = createTypeToken();
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.POST(url, client, gson, typeToken, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.typeToken, is(typeToken));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasAuthorizationHeader(TOKEN));
    }

    @Test
    public void shouldCreateVoidPOSTRequest() throws Exception {
        final MockRequest<Void, Auth0Exception> request = (MockRequest<Void, Auth0Exception>) factory.POST(url, client, gson, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.clazz, Is.<Class<Void>>is(Void.class));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasNoAuthorizationHeader());
    }

    @Test
    public void shouldCreateAuthorizedVoidPOSTRequest() throws Exception {
        final MockRequestFactory factory = createAuthorizedFactory();
        final MockRequest<Void, Auth0Exception> request = (MockRequest<Void, Auth0Exception>) factory.POST(url, client, gson, builder);

        TypeToken<Void> typeToken = createTypeToken();
        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.typeToken, is(typeToken));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasAuthorizationHeader(TOKEN));
    }

    @Test
    public void shouldCreateRawPOSTRequest() throws Exception {
        final MockRequest<Map<String, Object>, Auth0Exception> request = (MockRequest<Map<String, Object>, Auth0Exception>) factory.rawPOST(url, client, gson, builder);
        final TypeToken<Map<String, Object>> typeToken = createTypeToken();

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.typeToken, is(typeToken));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasNoAuthorizationHeader());
    }

    @Test
    public void shouldCreateAuthorizedRawPOSTRequest() throws Exception {
        final MockRequestFactory factory = createAuthorizedFactory();
        final MockRequest<Map<String, Object>, Auth0Exception> request = (MockRequest<Map<String, Object>, Auth0Exception>) factory.rawPOST(url, client, gson, builder);
        final TypeToken<Map<String, Object>> typeToken = createTypeToken();

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.typeToken, is(typeToken));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_POST)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasAuthorizationHeader(TOKEN));
    }

    @Test
    public void shouldCreatePATCHRequestOfTClass() throws Exception {
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.PATCH(url, client, gson, Auth0.class, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.clazz, Is.<Class<Auth0>>is((Auth0.class)));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_PATCH)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasNoAuthorizationHeader());
    }

    @Test
    public void shouldCreateAuthorizedPATCHRequestOfTClass() throws Exception {
        final MockRequestFactory factory = createAuthorizedFactory();
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.PATCH(url, client, gson, Auth0.class, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.clazz, Is.<Class<Auth0>>is((Auth0.class)));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_PATCH)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasAuthorizationHeader(TOKEN));
    }

    @Test
    public void shouldCreateDELETERequestOfTToken() throws Exception {
        TypeToken<Auth0> typeToken = createTypeToken();
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.DELETE(url, client, gson, typeToken, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.typeToken, is(typeToken));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_DELETE)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasNoAuthorizationHeader());
    }

    @Test
    public void shouldCreateAuthorizedDELETERequestOfTToken() throws Exception {
        final MockRequestFactory factory = createAuthorizedFactory();
        TypeToken<Auth0> typeToken = createTypeToken();
        final MockRequest<Auth0, Auth0Exception> request = (MockRequest<Auth0, Auth0Exception>) factory.DELETE(url, client, gson, typeToken, builder);

        assertThat(request.url, is(equalTo(url)));
        assertThat(request.client, is(equalTo(client)));
        assertThat(request.gson, is(equalTo(gson)));
        assertThat(request.typeToken, is(typeToken));
        assertThat(request.builder, is(equalTo(builder)));

        assertThat(request.method, is(equalTo(METHOD_DELETE)));
        assertThat(request, hasClientInfoHeader(CLIENT_INFO));
        assertThat(request, hasUserAgentHeader(USER_AGENT));
        assertThat(request, hasAuthorizationHeader(TOKEN));
    }

    private <T> TypeToken<T> createTypeToken() {
        return new TypeToken<T>() {
        };
    }


    private MockRequestFactory createBasicFactory() {
        MockRequestFactory factory = new MockRequestFactory();
        factory.setClientInfo(CLIENT_INFO);
        factory.setUserAgent(USER_AGENT);
        return factory;
    }

    private MockRequestFactory createAuthorizedFactory() {
        MockRequestFactory factory = new MockRequestFactory(TOKEN);
        factory.setClientInfo(CLIENT_INFO);
        factory.setUserAgent(USER_AGENT);
        return factory;
    }

}