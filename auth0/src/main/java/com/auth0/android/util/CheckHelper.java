package com.auth0.android.util;

import androidx.annotation.NonNull;

/**
 * A helper to check constructor arguments.
 */
public class CheckHelper {

    public static void checkArgument(boolean expression, @NonNull String message) throws RuntimeException {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }
}
