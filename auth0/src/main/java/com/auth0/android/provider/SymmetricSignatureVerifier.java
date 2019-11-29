package com.auth0.android.provider;

import android.support.annotation.NonNull;

import com.auth0.android.jwt.JWT;

/**
 * Token signature verifier for HS256 algorithms.
 */
class SymmetricSignatureVerifier extends SignatureVerifier {

    @Override
    void verifySignature(@NonNull JWT token) throws TokenValidationException {
        //NO-OP
        //HS256 (symmetric) signatures cannot be calculated on non-confidential clients
    }
}
