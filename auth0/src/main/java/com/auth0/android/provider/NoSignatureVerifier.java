package com.auth0.android.provider;

class NoSignatureVerifier extends SignatureVerifier {

    private static final String EXPECTED_ALGORITHM = "HS256";

    NoSignatureVerifier() {
        super(EXPECTED_ALGORITHM);
        //TODO: anything missing?
    }

}
