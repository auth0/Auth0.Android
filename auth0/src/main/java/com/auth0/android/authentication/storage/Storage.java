package com.auth0.android.authentication.storage;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * Abstract class that represents a Storage of key-value data.
 */
@SuppressWarnings("WeakerAccess")
public abstract class Storage {

    /**
     * Save a given value in the Storage.
     *
     * @param name  the name of the value to save.
     * @param value the value to save. Can be null.
     */
    public abstract void save(@NonNull String name, @Nullable String value);

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    @Nullable
    public abstract String retrieve(@NonNull String name);
}
