package com.auth0.android.util;

import android.app.Dialog;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.provider.AuthCallback;
import com.auth0.android.result.Credentials;
import com.jayway.awaitility.core.ConditionTimeoutException;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import static com.jayway.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class AuthCallbackMatcher extends BaseMatcher<AuthCallback> {
    private final Matcher<Credentials> payloadMatcher;
    private final Matcher<AuthenticationException> errorMatcher;
    private final Matcher<Dialog> dialogMatcher;

    public AuthCallbackMatcher(Matcher<Credentials> payloadMatcher, Matcher<AuthenticationException> errorMatcher, Matcher<Dialog> dialogMatcher) {
        this.payloadMatcher = payloadMatcher;
        this.errorMatcher = errorMatcher;
        this.dialogMatcher = dialogMatcher;
    }

    @Override
    public boolean matches(Object item) {
        MockAuthCallback callback = (MockAuthCallback) item;
        try {
            await().until(callback.credentials(), payloadMatcher);
            await().until(callback.error(), errorMatcher);
            await().until(callback.dialog(), dialogMatcher);
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

    public static Matcher<AuthCallback> hasCredentials() {
        return new AuthCallbackMatcher(is(notNullValue(Credentials.class)), is(nullValue(AuthenticationException.class)), is(nullValue(Dialog.class)));
    }

    public static Matcher<AuthCallback> hasError() {
        return new AuthCallbackMatcher(is(nullValue(Credentials.class)), is(notNullValue(AuthenticationException.class)), is(nullValue(Dialog.class)));
    }

    public static Matcher<AuthCallback> hasErrorDialog() {
        return new AuthCallbackMatcher(is(nullValue(Credentials.class)), is(nullValue(AuthenticationException.class)), is(notNullValue(Dialog.class)));
    }
}
