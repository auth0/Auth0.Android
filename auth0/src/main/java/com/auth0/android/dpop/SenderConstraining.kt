package com.auth0.android.dpop

/**
 * Interface for SenderConstraining
 */
public interface SenderConstraining<T : SenderConstraining<T>> {

    /**
     * Method to enable DPoP in the request.
     */
    public fun useDPoP(): T
}