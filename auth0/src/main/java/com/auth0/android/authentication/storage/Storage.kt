package com.auth0.android.authentication.storage;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

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
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    void store(@NonNull String name, @Nullable Boolean value);

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

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    @Nullable
    Boolean retrieveBoolean(@NonNull String name);

    /**
     * Removes a value from the storage.
     *
     * @param name the name of the value to remove.
     */
    void remove(@NonNull String name);
}
