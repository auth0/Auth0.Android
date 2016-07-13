package com.auth0.android.request.internal;

import android.support.annotation.NonNull;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

public class HeaderMatcher extends BaseMatcher<BaseRequest> {

    private final String name;
    private final String value;

    private HeaderMatcher(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public static HeaderMatcher hasAuthorizationHeader(@NonNull String value) {
        return new HeaderMatcher(RequestFactory.AUTHORIZATION_HEADER, "Bearer " + value);
    }

    public static HeaderMatcher hasNoAuthorizationHeader() {
        return new HeaderMatcher(RequestFactory.AUTHORIZATION_HEADER, null);
    }

    public static HeaderMatcher hasClientInfoHeader(@NonNull String value) {
        return new HeaderMatcher(RequestFactory.CLIENT_INFO_HEADER, value);
    }

    public static HeaderMatcher hasNoClientInfoHeader() {
        return new HeaderMatcher(RequestFactory.CLIENT_INFO_HEADER, null);
    }

    public static HeaderMatcher hasUserAgentHeader(@NonNull String value) {
        return new HeaderMatcher(RequestFactory.USER_AGENT_HEADER, value);
    }

    public static HeaderMatcher hasNoUserAgentHeader() {
        return new HeaderMatcher(RequestFactory.USER_AGENT_HEADER, null);
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("has header (" + name + ") with value (" + value + ")");
    }

    @Override
    public void describeMismatch(final Object item, final Description description) {
        BaseRequest request = (BaseRequest) item;
        if (request == null) {
            description.appendText("request was null");
            return;
        }
        description.appendText("was ").appendValue(getHeaderValue(request));
    }

    @Override
    public boolean matches(Object item) {
        BaseRequest request = (BaseRequest) item;
        if (request == null) {
            return false;
        }
        String headerValue = getHeaderValue(request);
        return headerValue == null && value == null || value.equals(headerValue);
    }

    private String getHeaderValue(BaseRequest request) {
        return (String) request.getHeaders().get(name);
    }
}