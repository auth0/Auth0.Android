package com.auth0.android.util;

import com.auth0.android.Auth0Exception;
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

public class CallbackMatcher<T, U extends Auth0Exception> extends BaseMatcher<MockCallback<T, U>> {
    private final Matcher<T> payloadMatcher;
    private final Matcher<U> errorMatcher;

    public CallbackMatcher(Matcher<T> payloadMatcher, Matcher<U> errorMatcher) {
        this.payloadMatcher = payloadMatcher;
        this.errorMatcher = errorMatcher;
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean matches(Object item) {
        MockCallback<T, U> callback = (MockCallback<T, U>) item;
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

    public static <T, U extends Auth0Exception> Matcher<MockCallback<T, U>> hasPayloadOfType(Class<T> tClazz, Class<U> uClazz) {
        return new CallbackMatcher<>(isA(tClazz), is(nullValue(uClazz)));
    }

    public static <T, U extends Auth0Exception> Matcher<MockCallback<T, U>> hasPayload(T payload, Class<U> uClazz) {
        return new CallbackMatcher<>(equalTo(payload), is(nullValue(uClazz)));
    }

    public static <T, U extends Auth0Exception> Matcher<MockCallback<T, U>> hasNoPayloadOfType(Class<T> tClazz, Class<U> uClazz) {
        return new CallbackMatcher<>(is(nullValue(tClazz)), is(notNullValue(uClazz)));
    }

    public static <U extends Auth0Exception> Matcher<MockCallback<Void, U>> hasNoError(Class<U> uClazz) {
        return new CallbackMatcher<>(is(nullValue(Void.class)), is(nullValue(uClazz)));
    }

    public static <U extends Auth0Exception> Matcher<MockCallback<Void, U>> hasError(Class<U> uClazz) {
        return new CallbackMatcher<>(is(nullValue(Void.class)), is(notNullValue(uClazz)));
    }
}
