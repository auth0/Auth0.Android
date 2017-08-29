package com.auth0.android.authentication.storage;

/**
 * Created by lbalmaceda on 8/29/17.
 */

/**
 * Exception thrown by the {@link CryptoUtil} class whenever an operation goes wrong.
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
