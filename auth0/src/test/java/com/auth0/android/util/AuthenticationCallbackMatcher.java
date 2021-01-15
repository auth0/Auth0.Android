package com.auth0.android.util;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.jayway.awaitility.core.ConditionTimeoutException;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import static com.jayway.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isA;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class AuthenticationCallbackMatcher<T> extends BaseMatcher<AuthenticationCallback<T>> {
    private final Matcher<T> payloadMatcher;
    private final Matcher<AuthenticationException> errorMatcher;

    public AuthenticationCallbackMatcher(Matcher<T> payloadMatcher, Matcher<AuthenticationException> errorMatcher) {
        this.payloadMatcher = payloadMatcher;
        this.errorMatcher = errorMatcher;
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean matches(Object item) {
        MockAuthenticationCallback<T> callback = (MockAuthenticationCallback<T>) item;
        try {
            await().until(callback.payload(), payloadMatcher);
            await().until(callback.error(), errorMatcher);
            return true;
        } catch (ConditionTimeoutException e) {
            return false;
        }
    }

    @Override
    public void describeTo(Description description) {
        description
                .appendText("successful method be called");
    }

    public static <T> Matcher<AuthenticationCallback<T>> hasPayloadOfType(Class<T> tClazz) {
        return new AuthenticationCallbackMatcher<>(isA(tClazz), is(nullValue(AuthenticationException.class)));
    }

    public static <T> Matcher<AuthenticationCallback<T>> hasPayload(T payload) {
        return new AuthenticationCallbackMatcher<>(equalTo(payload), is(nullValue(AuthenticationException.class)));
    }

    public static <T> Matcher<AuthenticationCallback<T>> hasNoPayloadOfType(Class<T> tClazz) {
        return new AuthenticationCallbackMatcher<>(is(nullValue(tClazz)), is(notNullValue(AuthenticationException.class)));
    }

    public static Matcher<AuthenticationCallback<Void>> hasNoError() {
        return new AuthenticationCallbackMatcher<>(is(nullValue(Void.class)), is(nullValue(AuthenticationException.class)));
    }

    public static <T> Matcher<AuthenticationCallback<T>> hasError(Class<T> tClazz) {
        return new AuthenticationCallbackMatcher<>(is(nullValue(tClazz)), is(notNullValue(AuthenticationException.class)));
    }
}
