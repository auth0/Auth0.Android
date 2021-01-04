package com.auth0.android.authentication.storage

/**
 * Exception thrown by the [CryptoUtil] class whenever the Keys are deemed invalid
 * and so the content encrypted with them unrecoverable.
 */
internal class IncompatibleDeviceException(cause: Throwable?) : CryptoException(
    "The device is not compatible with the ${CryptoUtil::class.java.simpleName} class.", cause
)