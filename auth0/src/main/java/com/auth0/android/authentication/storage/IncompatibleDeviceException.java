package com.auth0.android.authentication.storage;

/**
 * Exception thrown by the {@link CryptoUtil} class whenever the Keys are deemed invalid
 * and so the content encrypted with them unrecoverable.
 */
public class IncompatibleDeviceException extends RuntimeException {
    IncompatibleDeviceException(Throwable cause) {
        super(String.format("The device is not compatible with the %s class.", CryptoUtil.class.getSimpleName()), cause);
    }
}
