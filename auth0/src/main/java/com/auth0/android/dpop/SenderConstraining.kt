package com.auth0.android.dpop

import android.content.Context

/**
 * Interface for SenderConstraining
 */
public interface SenderConstraining<T> {

    /**
     * Enables DPoP for authentication requests.
     */
    public fun useDPoP(context: Context): T

}