package com.auth0.android.authentication;

import com.auth0.android.Auth0Exception;

class KeyProviderException extends Auth0Exception {

    KeyProviderException(String message, Throwable e) {
        super(message, e);
    }
}
