package com.auth0.android.callback

import com.auth0.android.Auth0Exception

/**
 * Legacy interface to handle successful callbacks. Use {@linkplain Callback} instead.
 */
@Deprecated(
    message = "The contract of this interface has been migrated to the Callback interface",
    replaceWith = ReplaceWith("Callback")
)
public interface BaseCallback<T, U : Auth0Exception> : Callback<T, U>