package com.auth0.android.authentication.storage

/**
 * Exception thrown by the [CryptoUtil] class whenever an operation goes wrong.
 */
public open class CryptoException internal constructor(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)