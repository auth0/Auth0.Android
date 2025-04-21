package com.auth0.android.result

public class SSOCredentialsMock {

    public companion object {

        public fun create(
            accessToken: String,
            idToken:String ,
            issuedTokenType: String,
            type: String,
            refreshToken: String?,
            expiresIn: Int
        ): SSOCredentials {
            return SSOCredentials(
                accessToken,idToken, issuedTokenType, type, expiresIn, refreshToken
            )
        }
    }
}