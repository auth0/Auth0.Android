package com.auth0.android.util;

import com.auth0.android.callback.ManagementCallback;
import com.auth0.android.management.ManagementException;
import com.google.gson.reflect.TypeToken;
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

public class ManagementCallbackMatcher<T> extends BaseMatcher<ManagementCallback<T>> {
    private final Matcher<T> payloadMatcher;
    private final Matcher<ManagementException> errorMatcher;

    public ManagementCallbackMatcher(Matcher<T> payloadMatcher, Matcher<ManagementException> errorMatcher) {
        this.payloadMatcher = payloadMatcher;
        this.errorMatcher = errorMatcher;
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean matches(Object item) {
        MockManagementCallback<T> callback = (MockManagementCallback<T>) item;
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

    public static <T> Matcher<ManagementCallback<T>> hasPayloadOfType(Class<T> tClazz) {
        return new ManagementCallbackMatcher<>(isA(tClazz), is(nullValue(ManagementException.class)));
    }

    public static <T> Matcher<ManagementCallback<T>> hasPayloadOfType(TypeToken<T> typeToken) {
        return new ManagementCallbackMatcher<>(TypeTokenMatcher.isA(typeToken), is(nullValue(ManagementException.class)));
    }

    public static <T> Matcher<ManagementCallback<T>> hasPayload(T payload) {
        return new ManagementCallbackMatcher<>(equalTo(payload), is(nullValue(ManagementException.class)));
    }

    public static <T> Matcher<ManagementCallback<T>> hasNoPayloadOfType(Class<T> tClazz) {
        return new ManagementCallbackMatcher<>(is(nullValue(tClazz)), is(notNullValue(ManagementException.class)));
    }

    public static <T> Matcher<ManagementCallback<T>> hasNoPayloadOfType(TypeToken<T> typeToken) {
        return new ManagementCallbackMatcher<>(TypeTokenMatcher.isA(typeToken), is(nullValue(ManagementException.class)));
    }

    public static Matcher<ManagementCallback<Void>> hasNoError() {
        return new ManagementCallbackMatcher<>(is(notNullValue(Void.class)), is(nullValue(ManagementException.class)));
    }

    public static Matcher<ManagementCallback<Void>> hasError() {
        return new ManagementCallbackMatcher<>(is(nullValue(Void.class)), is(notNullValue(ManagementException.class)));
    }
}
