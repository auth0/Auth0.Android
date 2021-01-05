package com.auth0.android.util;

/**
 * The clock used for verification purposes.
 *
 * @see com.auth0.android.authentication.storage.SecureCredentialsManager
 * @see com.auth0.android.authentication.storage.CredentialsManager
 */
public interface Clock {
    /**
     * Returns the current time in milliseconds (epoch).
     *
     * @return the current time in milliseconds.
     */
    long getCurrentTimeMillis();
}
