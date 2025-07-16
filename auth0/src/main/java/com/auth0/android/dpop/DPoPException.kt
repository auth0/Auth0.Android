package com.auth0.android.dpop

import com.auth0.android.Auth0Exception

public class DPoPException : Auth0Exception {
    private var code: String? = null
    private var description: String? = null


    public constructor(code: String, description: String) : this(DEFAULT_MESSAGE) {
        this.code = code
        this.description = description
    }

    public constructor(message: String, cause: Exception? = null) : super(message, cause)

    private companion object {
        private const val DEFAULT_MESSAGE = "Unknown error"
    }
}