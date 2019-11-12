package com.auth0.android.jwt;

//TODO: Make pkg private
public class NoSignatureVerifier extends SignatureVerifier {

    private static final String EXPECTED_ALGORITHM = "HS256";

    public NoSignatureVerifier() {
        super(EXPECTED_ALGORITHM);
        //TODO: anything missing?
    }

}
