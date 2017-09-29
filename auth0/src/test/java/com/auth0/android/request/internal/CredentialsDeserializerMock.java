package com.auth0.android.request.internal;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.CredentialsMock;

import java.util.Date;

class CredentialsDeserializerMock extends CredentialsDeserializer {

    @Override
    long getCurrentTimeInMillis() {
        return CredentialsMock.CURRENT_TIME_MS;
    }

    @Override
    Credentials createCredentials(String idToken, String accessToken, String type, String refreshToken, Date expiresAt, String scope) {
        return new CredentialsMock(idToken, accessToken, type, refreshToken, expiresAt, scope);
    }
}