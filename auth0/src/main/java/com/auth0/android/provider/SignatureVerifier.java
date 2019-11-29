package com.auth0.android.provider;

import android.support.annotation.CallSuper;

import com.auth0.android.jwt.JWT;

//TODO: Make pkg private
abstract class SignatureVerifier {

    private final String expectedAlgorithm;

    SignatureVerifier(String expectedAlgorithm) {
        this.expectedAlgorithm = expectedAlgorithm;
    }

    private final void checkAlgorithm(JWT token) throws TokenValidationException {
        String algorithmName = token.getHeader().get("alg");
        if (!expectedAlgorithm.equals(algorithmName)) {
            throw new TokenValidationException(String.format("Signature algorithm of \"%s\" is not supported. Expected \"%s\".", algorithmName, expectedAlgorithm));
        }
    }

    @CallSuper
    void verifySignature(JWT token) throws TokenValidationException {
        checkAlgorithm(token);
    }

}
