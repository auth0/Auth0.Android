package com.auth0.android.authentication.storage;

/**
 * Exception thrown by the {@link CryptoUtil} class whenever the Keys are deemed invalid
 * and so the content encrypted with them unrecoverable.
 */
class UnrecoverableContentException extends CryptoException {
    UnrecoverableContentException(Throwable cause) {
        super("The cryptographic keys have been deleted and the content signed with them should be deemed unrecoverable.", cause);
    }
}
