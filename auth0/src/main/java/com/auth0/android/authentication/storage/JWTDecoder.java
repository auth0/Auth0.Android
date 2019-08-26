package com.auth0.android.authentication.storage;

import com.auth0.android.jwt.JWT;

/**
 * Bridge class for decoding JWTs.
 * Used to abstract the implementation for testing purposes.
 */
class JWTDecoder {

    JWTDecoder() {
    }

    JWT decode(String jwt) {
        return new JWT(jwt);
    }
}
