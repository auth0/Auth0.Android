package com.auth0.android.jwt;

import android.support.annotation.CallSuper;

//TODO: Make pkg private
public abstract class SignatureVerifier {

    private final String expectedAlgorithm;

    public SignatureVerifier(String expectedAlgorithm) {
        this.expectedAlgorithm = expectedAlgorithm;
    }

    private final void checkAlgorithm(JWT token) throws TokenValidationException {
        String algorithmName = token.getHeader().get("alg");
        if (!expectedAlgorithm.equals(algorithmName)) {
            throw new TokenValidationException(String.format("Signature algorithm of \"%s\" is not supported. Expected \"%s\".", algorithmName, expectedAlgorithm));
        }
    }

    @CallSuper
    public void verifySignature(JWT token) throws TokenValidationException {
        checkAlgorithm(token);
    }

}
