package com.auth0.android.result

import java.util.Date

public class SSOCredentialsMock {

    public companion object {

        public fun create(
            accessToken: String,
            idToken: String,
            issuedTokenType: String,
            type: String,
            refreshToken: String?,
            expiresIn: Date
        ): SSOCredentials {
            return SSOCredentials(
                accessToken, idToken, issuedTokenType, type, expiresIn, refreshToken
            )
        }
    }
}