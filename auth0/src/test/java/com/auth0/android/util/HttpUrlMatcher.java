package com.auth0.android.util;

import okhttp3.HttpUrl;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import static org.hamcrest.CoreMatchers.any;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;

public class HttpUrlMatcher extends BaseMatcher<HttpUrl> {

    private final Matcher<String> schemeMatcher;
    private final Matcher<String> hostMatcher;
    private final Matcher<Iterable<? extends String>> pathMatcher;

    private HttpUrlMatcher(Matcher<String> schemeMatcher, Matcher<String> hostMatcher, Matcher<Iterable<? extends String>> pathMatcher) {
        this.schemeMatcher = schemeMatcher;
        this.hostMatcher = hostMatcher;
        this.pathMatcher = pathMatcher;
    }

    public static HttpUrlMatcher hasScheme(String scheme) {
        return new HttpUrlMatcher(is(scheme), any(String.class), null);
    }

    public static HttpUrlMatcher hasHost(String host) {
        return new HttpUrlMatcher(any(String.class), is(host), null);
    }

    public static HttpUrlMatcher hasPath(String... path) {
        return new HttpUrlMatcher(any(String.class), any(String.class), contains(path));
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("a HttpUrl with ")
                .appendText("scheme: ").appendDescriptionOf(schemeMatcher).appendText(" ")
                .appendText("host: ").appendDescriptionOf(hostMatcher).appendText(" ");
        if (pathMatcher != null) {
            description.appendText("path: ").appendDescriptionOf(pathMatcher);
        }
    }

    @Override
    public boolean matches(Object item) {
        HttpUrl httpUrl = (HttpUrl) item;
        return httpUrl != null && hasScheme(httpUrl) && hasHost(httpUrl) && hasPath(httpUrl);
    }

    private boolean hasScheme(HttpUrl url) {
        return schemeMatcher.matches(url.scheme());
    }

    private boolean hasHost(HttpUrl url) {
        return hostMatcher.matches(url.host());
    }

    private boolean hasPath(HttpUrl url) {
        return pathMatcher == null || pathMatcher.matches(url.pathSegments());
    }

}