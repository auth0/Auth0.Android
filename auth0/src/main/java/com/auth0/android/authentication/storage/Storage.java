package com.auth0.android.authentication.storage;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * Represents a Storage of key-value data.
 * Supported classes are String, Long and Integer.
 */
@SuppressWarnings("WeakerAccess")
public interface Storage {

    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    void store(@NonNull String name, @Nullable Long value);

    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    void store(@NonNull String name, @Nullable Integer value);

    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    void store(@NonNull String name, @Nullable String value);

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    @Nullable
    Long retrieveLong(@NonNull String name);

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    @Nullable
    String retrieveString(@NonNull String name);

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    @Nullable
    Integer retrieveInteger(@NonNull String name);
}
