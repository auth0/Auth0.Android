package com.auth0.android.provider;

import androidx.annotation.NonNull;

public class AlgorithmHelperMock extends AlgorithmHelper {
    private final String codeVerifier;

    public AlgorithmHelperMock(@NonNull String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }

    @Override
    public String generateCodeVerifier() {
        return codeVerifier;
    }
}
