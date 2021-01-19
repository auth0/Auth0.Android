package com.auth0.android.authentication.storage;

import com.auth0.android.request.internal.Jwt;

/**
 * Bridge class for decoding JWTs.
 * Used to abstract the implementation for testing purposes.
 */
class JWTDecoder {

    JWTDecoder() {
    }

    Jwt decode(String jwt) {
        return new Jwt(jwt);
    }
}
