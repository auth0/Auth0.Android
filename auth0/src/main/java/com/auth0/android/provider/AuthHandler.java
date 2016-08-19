package com.auth0.android.provider;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

@SuppressWarnings("unused")
public interface AuthHandler {

    /**
     * Get an AuthProvider that can handle a given strategy and connection name, or null if there are no
     * providers to handle them.
     *
     * @param strategy   to handle
     * @param connection to handle
     * @return an AuthProvider to handle the authentication or null if no providers are available.
     */
    @Nullable
    AuthProvider providerFor(@NonNull String strategy, @NonNull String connection);
}
