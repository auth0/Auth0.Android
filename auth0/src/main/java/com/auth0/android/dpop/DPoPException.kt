package com.auth0.android.dpop

import com.auth0.android.Auth0Exception

public class DPoPException : Auth0Exception {

    public enum class Code {
        KEY_GENERATION_ERROR,
        KEY_STORE_ERROR,
        UNKNOWN,
    }
    
    private var code: Code? = null

    internal constructor(
        code: Code,
        cause: Throwable? = null
    ) : this(
        code,
        getMessage(code),
        cause
    )

    internal constructor(
        code: Code,
        message: String,
        cause: Throwable? = null
    ) : super(
        message,
        cause
    ) {
        this.code = code
    }


    private companion object {
        private const val DEFAULT_MESSAGE =
            "An unknown error has occurred. Please check the error cause for more details."

        private fun getMessage(code: Code): String {
            return when (code) {
                Code.KEY_GENERATION_ERROR -> "Error generating DPoP key pair."
                Code.KEY_STORE_ERROR -> "Error while accessing the key pair in the keystore."
                Code.UNKNOWN -> DEFAULT_MESSAGE
            }
        }
    }
}