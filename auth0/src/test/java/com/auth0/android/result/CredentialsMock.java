package com.auth0.android.result;

import android.support.annotation.Nullable;

import java.util.Date;

@SuppressWarnings("WeakerAccess")
public class CredentialsMock extends Credentials {

    public static final long CURRENT_TIME_MS = 1234567890000L;

    public CredentialsMock(@Nullable String idToken, @Nullable String accessToken, @Nullable String type, @Nullable String refreshToken, @Nullable Long expiresIn) {
        super(idToken, accessToken, type, refreshToken, expiresIn);
    }

    public CredentialsMock(@Nullable String idToken, @Nullable String accessToken, @Nullable String type, @Nullable String refreshToken, @Nullable Date expiresAt, @Nullable String scope) {
        super(idToken, accessToken, type, refreshToken, expiresAt, scope);
    }

    @Override
    long getCurrentTimeInMillis() {
        return CURRENT_TIME_MS;
    }
}