package com.auth0.android.request

import com.auth0.android.Auth0Exception

/**
 * Interface for validating request parameters before execution.
 * Validators are invoked before the network request is made.
 */
public interface RequestValidator {

    /**
     * Validates the request options and parameters.
     * @param options the request options to validate
     * @throws Auth0Exception if validation fails
     */
    @Throws(Auth0Exception::class)
    public fun validate(options: RequestOptions)
}