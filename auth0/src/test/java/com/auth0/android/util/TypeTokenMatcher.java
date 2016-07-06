package com.auth0.android.util;

import com.google.gson.reflect.TypeToken;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

public class TypeTokenMatcher<T> extends BaseMatcher<T> {
    private final TypeToken<T> typeToken;

    private TypeTokenMatcher(TypeToken<T> typeToken) {
        this.typeToken = typeToken;
    }

    public static <T> TypeTokenMatcher<T> isA(TypeToken<T> typeToken) {
        return new TypeTokenMatcher<>(typeToken);
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("isA(" + typeToken.toString() + ")");
    }

    @Override
    public boolean matches(Object item) {
        return item != null && typeToken.getRawType().isAssignableFrom(item.getClass());
    }
}