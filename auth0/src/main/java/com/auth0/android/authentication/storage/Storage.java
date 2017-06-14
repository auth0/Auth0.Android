package com.auth0.android.authentication.storage;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * Represents a Storage of key-value data.
 */
@SuppressWarnings("WeakerAccess")
public interface Storage {

    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to save.
     * @param value the value to save. Can be null.
     */
    void store(@NonNull String name, @Nullable String value);

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    @Nullable
    String retrieve(@NonNull String name);
}
