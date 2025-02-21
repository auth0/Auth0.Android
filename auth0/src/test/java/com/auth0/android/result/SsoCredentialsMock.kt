package com.auth0.android.result

public class SsoCredentialsMock {

    public companion object {

        public fun create(
            accessToken: String,
            issuedTokenType: String,
            type: String,
            refreshToken: String?,
            expiresIn: Int
        ): SSOCredentials {
            return SSOCredentials(
                accessToken, issuedTokenType, type, expiresIn, refreshToken
            )
        }
    }
}