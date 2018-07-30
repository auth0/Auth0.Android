package com.auth0.android.verification;

import com.auth0.android.Auth0Exception;

class KeyProviderException extends Auth0Exception {

    public KeyProviderException(String message, Throwable e) {
        super(message, e);
    }
}
