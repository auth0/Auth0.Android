package com.auth0.android.provider

import com.auth0.android.Auth0Exception

/**
 * Exception thrown when the validation of the ID token failed.
 */
internal class TokenValidationException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null
) :
    Auth0Exception(message, cause)