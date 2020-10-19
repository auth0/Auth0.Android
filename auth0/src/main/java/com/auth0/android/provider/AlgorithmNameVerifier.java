package com.auth0.android.provider;

import androidx.annotation.NonNull;

import java.util.Arrays;

/**
 * Token signature verifier for RSH256 and/or HS256 algorithms.
 */
class AlgorithmNameVerifier extends SignatureVerifier {

    AlgorithmNameVerifier() {
        super(Arrays.asList("HS256", "RS256"));
    }

    @Override
    protected void checkSignature(@NonNull String[] tokenParts) throws TokenValidationException {
        //NO-OP
    }
}
