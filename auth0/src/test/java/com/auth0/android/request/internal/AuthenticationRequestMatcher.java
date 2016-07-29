package com.auth0.android.request.internal;

import com.squareup.okhttp.HttpUrl;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

public class AuthenticationRequestMatcher<T> extends BaseMatcher<MockAuthenticationRequest> {

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
                    RequestFactory.ACCEPT_LANGUAGE_HEADER, acceptLanguageValue,
                    RequestFactory.CLIENT_INFO_HEADER, clientInfoValue,
                    RequestFactory.USER_AGENT_HEADER, userAgentValue));
            if (authorizationValue != null) {
                description.appendText(String.format(", (%s) with value (%s)", RequestFactory.AUTHORIZATION_HEADER, authorizationValue));
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
                    RequestFactory.ACCEPT_LANGUAGE_HEADER, getHeaderValue(request, RequestFactory.ACCEPT_LANGUAGE_HEADER),
                    RequestFactory.CLIENT_INFO_HEADER, getHeaderValue(request, RequestFactory.CLIENT_INFO_HEADER),
                    RequestFactory.USER_AGENT_HEADER, getHeaderValue(request, RequestFactory.USER_AGENT_HEADER)));
            if (authorizationValue != null) {
                description.appendText(String.format(", (%s) was (%s)",
                        RequestFactory.AUTHORIZATION_HEADER, getHeaderValue(request, RequestFactory.AUTHORIZATION_HEADER)));
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
        return objectEquals(acceptLanguageValue, getHeaderValue(request, RequestFactory.ACCEPT_LANGUAGE_HEADER));
    }

    private boolean hasAuthorizationHeader(MockAuthenticationRequest request) {
        return objectEquals(authorizationValue, getHeaderValue(request, RequestFactory.AUTHORIZATION_HEADER));
    }

    private boolean hasUserAgentHeader(MockAuthenticationRequest request) {
        return objectEquals(userAgentValue, getHeaderValue(request, RequestFactory.USER_AGENT_HEADER));
    }

    private boolean hasClientInfoHeader(MockAuthenticationRequest request) {
        return objectEquals(clientInfoValue, getHeaderValue(request, RequestFactory.CLIENT_INFO_HEADER));
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