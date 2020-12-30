package com.auth0.android.authentication.storage

/**
 * Represents a Storage of key-value data.
 * Supported classes are String, Long and Integer.
 */
public interface Storage {
    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    public fun store(name: String, value: Long?)

    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    public fun store(name: String, value: Int?)

    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    public fun store(name: String, value: String?)

    /**
     * Store a given value in the Storage.
     *
     * @param name  the name of the value to store.
     * @param value the value to store. Can be null.
     */
    public fun store(name: String, value: Boolean?)

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    public fun retrieveLong(name: String): Long?

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    public fun retrieveString(name: String): String?

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    public fun retrieveInteger(name: String): Int?

    /**
     * Retrieve a value from the Storage.
     *
     * @param name the name of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     */
    public fun retrieveBoolean(name: String): Boolean?

    /**
     * Removes a value from the storage.
     *
     * @param name the name of the value to remove.
     */
    public fun remove(name: String)
}