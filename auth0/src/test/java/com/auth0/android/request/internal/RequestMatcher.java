package com.auth0.android.request.internal;

import com.google.gson.reflect.TypeToken;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

import okhttp3.HttpUrl;

public class RequestMatcher<T> extends BaseMatcher<MockRequest> {

    private static final String ACCEPT_LANGUAGE_HEADER = "Accept-Language";
    private static final String CLIENT_INFO_HEADER = "Auth0-Client";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String USER_AGENT_HEADER = "User-Agent";
    private final boolean checkHeaders;
    private String acceptLanguageValue;
    private String clientInfoValue;
    private String userAgentValue;
    private String authorizationValue;

    private HttpUrl url;
    private String method;
    private Class<T> clazz;
    private TypeToken<T> typeToken;

    private RequestMatcher(String acceptLanguageValue, String clientInfoValue, String userAgentValue, String authorizationValue) {
        checkHeaders = true;
        this.acceptLanguageValue = acceptLanguageValue;
        this.clientInfoValue = clientInfoValue;
        this.userAgentValue = userAgentValue;
        this.authorizationValue = authorizationValue;
    }

    private RequestMatcher(HttpUrl url, String method) {
        this(url, method, null, null);
    }

    private RequestMatcher(HttpUrl url, String method, Class<T> clazz, TypeToken<T> typeToken) {
        checkHeaders = false;
        this.url = url;
        this.method = method;
        this.clazz = clazz;
        this.typeToken = typeToken;
    }

    public static RequestMatcher hasHeaders(String acceptLanguageValue, String clientInfoValue, String userAgentValue, String authorizationValue) {
        return new RequestMatcher(acceptLanguageValue, clientInfoValue, userAgentValue, authorizationValue);
    }

    public static RequestMatcher hasHeaders(String acceptLanguageValue, String clientInfoValue, String userAgentValue) {
        return new RequestMatcher(acceptLanguageValue, clientInfoValue, userAgentValue, null);
    }

    public static <T> RequestMatcher hasArguments(HttpUrl url, String httpMethod, Class<T> clazz) {
        return new RequestMatcher<>(url, httpMethod, clazz, null);
    }

    public static <T> RequestMatcher hasArguments(HttpUrl url, String httpMethod, TypeToken<T> typeToken) {
        return new RequestMatcher<>(url, httpMethod, null, typeToken);
    }

    public static RequestMatcher hasArguments(HttpUrl url, String httpMethod) {
        return new RequestMatcher(url, httpMethod);
    }

    @Override
    public void describeTo(Description description) {
        if (checkHeaders) {
            description.appendText(String.format("to have headers: (%s) with value (%s), (%s) with value (%s), (%s) with value (%s)",
                    ACCEPT_LANGUAGE_HEADER, acceptLanguageValue,
                    CLIENT_INFO_HEADER, clientInfoValue,
                    USER_AGENT_HEADER, userAgentValue));
            if (authorizationValue != null) {
                description.appendText(String.format(", (%s) with value (%s)", AUTHORIZATION_HEADER, authorizationValue));
            }
            return;
        }

        description.appendText(String.format("to have arguments: (URL) with value (%s), (HttpMethod) with value (%s)",
                url, method));
        if (clazz != null) {
            description.appendText(String.format(", (Class) with value (%s)",
                    clazz));
        }
        if (typeToken != null) {
            description.appendText(String.format(", (TypeToken) with value (%s)",
                    typeToken));
        }
    }

    @Override
    public void describeMismatch(final Object item, final Description description) {
        MockRequest request = (MockRequest) item;
        if (request == null) {
            description.appendText("request was null");
            return;
        }

        if (checkHeaders) {
            description.appendText(String.format("header (%s) was (%s), (%s) was (%s), (%s) was (%s)",
                    ACCEPT_LANGUAGE_HEADER, getHeaderValue(request, ACCEPT_LANGUAGE_HEADER),
                    CLIENT_INFO_HEADER, getHeaderValue(request, CLIENT_INFO_HEADER),
                    USER_AGENT_HEADER, getHeaderValue(request, USER_AGENT_HEADER)));
            if (authorizationValue != null) {
                description.appendText(String.format(", (%s) was (%s)",
                        AUTHORIZATION_HEADER, getHeaderValue(request, AUTHORIZATION_HEADER)));
            }
            return;
        }

        description.appendText(String.format("argument (URL) was (%s), (HttpMethod) was (%s)",
                request.url, request.method));
        if (clazz != null) {
            description.appendText(String.format(", (Class) was (%s)",
                    request.clazz));
        }
        if (typeToken != null) {
            description.appendText(String.format(", (TypeToken) was (%s)",
                    request.typeToken));
        }
    }

    @Override
    public boolean matches(Object item) {
        if (item == null) {
            return false;
        }

        MockRequest mockRequest = (MockRequest) item;
        if (checkHeaders) {
            final boolean acceptLanguage = hasAcceptLanguageHeader(mockRequest);
            final boolean clientInfo = hasClientInfoHeader(mockRequest);
            final boolean userAgent = hasUserAgentHeader(mockRequest);
            final boolean authorization = hasAuthorizationHeader(mockRequest);
            return acceptLanguage && clientInfo && userAgent && authorization;
        }

        final boolean url = objectEquals(mockRequest.url, this.url);
        final boolean method = objectEquals(mockRequest.method, this.method);
        final boolean clazz = sameClass(mockRequest.clazz, this.clazz);
        final boolean typeToken = sameTypeToken(mockRequest.typeToken, this.typeToken);
        return url && method && clazz && typeToken;
    }

    private boolean hasAcceptLanguageHeader(MockRequest request) {
        return objectEquals(acceptLanguageValue, getHeaderValue(request, ACCEPT_LANGUAGE_HEADER));
    }

    private boolean hasAuthorizationHeader(MockRequest request) {
        return objectEquals(authorizationValue, getHeaderValue(request, AUTHORIZATION_HEADER));
    }

    private boolean hasUserAgentHeader(MockRequest request) {
        return objectEquals(userAgentValue, getHeaderValue(request, USER_AGENT_HEADER));
    }

    private boolean hasClientInfoHeader(MockRequest request) {
        return objectEquals(clientInfoValue, getHeaderValue(request, CLIENT_INFO_HEADER));
    }

    private String getHeaderValue(MockRequest request, String name) {
        return (String) request.headers.get(name);
    }

    private boolean objectEquals(Object a, Object b) {
        if (a == null && b == null) {
            return true;
        } else if (a == null ^ b == null) {
            return false;
        } else if (a.equals(b)) {
            return true;
        }
        return false;
    }

    private boolean sameClass(Class<?> a, Class<?> b) {
        if (a == null && b == null) {
            return true;
        } else if (a == null ^ b == null) {
            return false;
        } else if (a.isAssignableFrom(b)) {
            return true;
        }
        return false;
    }

    private boolean sameTypeToken(TypeToken a, TypeToken b) {
        if (a == null && b == null) {
            return true;
        } else if (a == null ^ b == null) {
            return false;
        } else if (sameClass(b.getRawType(), a.getRawType())) {
            return true;
        }
        return false;
    }
}