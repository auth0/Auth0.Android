package com.auth0.android.provider;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

@SuppressWarnings("unused")
public interface AuthHandler {

    /**
     * Tries to supply an AuthProvider for a given strategy and connection name. If it can't provide one it will return null.
     *
     * @param strategy   name of the strategy to provide an Auth handler for
     * @param connection name of the connection to provide an Auth handler for
     * @return an AuthProvider to handle the authentication or null.
     */
    @Nullable
    AuthProvider providerFor(@NonNull String strategy, @NonNull String connection);
}
