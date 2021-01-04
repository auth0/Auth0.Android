package com.auth0.android.authentication.storage;

/**
 * Exception thrown by the {@link CryptoUtil} class whenever an operation goes wrong.
 */
public class CryptoException extends RuntimeException {
    CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
