package com.auth0.android.request.internal;


import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

import okhttp3.HttpUrl;

public class AuthenticationRequestMatcher<T> extends BaseMatcher<MockAuthenticationRequest> {

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

    private AuthenticationRequestMatcher(String acceptLanguageValue, String clientInfoValue, String userAgentValue, String authorizationValue) {
        checkHeaders = true;
        this.acceptLanguageValue = acceptLanguageValue;
        this.clientInfoValue = clientInfoValue;
        this.userAgentValue = userAgentValue;
        this.authorizationValue = authorizationValue;
    }

    private AuthenticationRequestMatcher(HttpUrl url, String method) {
        checkHeaders = false;
        this.url = url;
        this.method = method;
    }

    public static AuthenticationRequestMatcher hasHeaders(String acceptLanguageValue, String clientInfoValue, String userAgentValue, String authorizationValue) {
        return new AuthenticationRequestMatcher(acceptLanguageValue, clientInfoValue, userAgentValue, authorizationValue);
    }

    public static AuthenticationRequestMatcher hasHeaders(String acceptLanguageValue, String clientInfoValue, String userAgentValue) {
        return new AuthenticationRequestMatcher(acceptLanguageValue, clientInfoValue, userAgentValue, null);
    }

    public static AuthenticationRequestMatcher hasArguments(HttpUrl url, String httpMethod) {
        return new AuthenticationRequestMatcher(url, httpMethod);
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
    }

    @Override
    public void describeMismatch(final Object item, final Description description) {
        MockAuthenticationRequest request = (MockAuthenticationRequest) item;
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
    }

    @Override
    public boolean matches(Object item) {
        if (item == null) {
            return false;
        }

        MockAuthenticationRequest mockRequest = (MockAuthenticationRequest) item;
        if (checkHeaders) {
            final boolean acceptLanguage = hasAcceptLanguageHeader(mockRequest);
            final boolean clientInfo = hasClientInfoHeader(mockRequest);
            final boolean userAgent = hasUserAgentHeader(mockRequest);
            final boolean authorization = hasAuthorizationHeader(mockRequest);
            return acceptLanguage && clientInfo && userAgent && authorization;
        }

        final boolean url = objectEquals(mockRequest.url, this.url);
        final boolean method = objectEquals(mockRequest.method, this.method);
        return url && method;
    }

    private boolean hasAcceptLanguageHeader(MockAuthenticationRequest request) {
        return objectEquals(acceptLanguageValue, getHeaderValue(request, ACCEPT_LANGUAGE_HEADER));
    }

    private boolean hasAuthorizationHeader(MockAuthenticationRequest request) {
        return objectEquals(authorizationValue, getHeaderValue(request, AUTHORIZATION_HEADER));
    }

    private boolean hasUserAgentHeader(MockAuthenticationRequest request) {
        return objectEquals(userAgentValue, getHeaderValue(request, USER_AGENT_HEADER));
    }

    private boolean hasClientInfoHeader(MockAuthenticationRequest request) {
        return objectEquals(clientInfoValue, getHeaderValue(request, CLIENT_INFO_HEADER));
    }

    private String getHeaderValue(MockAuthenticationRequest request, String name) {
        return request.headers.get(name);
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
}