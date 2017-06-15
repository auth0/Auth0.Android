package com.auth0.android.authentication.storage;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * Represents a Storage of generic key-value data.
 */
@SuppressWarnings("WeakerAccess")
public interface Storage {

    /**
     * Store a given value in the Storage.
     *
     * @param name   the name of the value to store.
     * @param value  the value to store. Can be null.
     * @param tClazz the class of the value to store.
     * @param <T>    the type of the value to store.
     */
    <T> void store(@NonNull String name, @Nullable T value, @NonNull Class<T> tClazz);

    /**
     * Retrieve a value from the Storage.
     *
     * @param name   the name of the value to retrieve.
     * @param tClazz the class of the value to retrieve.
     * @param <T>    the type of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    @Nullable
    <T> T retrieve(@NonNull String name, @NonNull Class<T> tClazz);
}
