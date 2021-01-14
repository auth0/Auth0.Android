package com.auth0.android.provider

import com.auth0.android.Auth0Exception

/**
 * Exception thrown when the validation of the ID token failed.
 */
internal class TokenValidationException(message: String) : Auth0Exception(message)