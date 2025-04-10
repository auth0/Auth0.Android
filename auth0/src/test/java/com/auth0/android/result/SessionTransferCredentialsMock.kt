package com.auth0.android.result

public class SessionTransferCredentialsMock {

    public companion object {

        public fun create(
            accessToken: String,
            idToken:String ,
            issuedTokenType: String,
            type: String,
            refreshToken: String?,
            expiresIn: Int
        ): SessionTransferCredentials {
            return SessionTransferCredentials(
                accessToken,idToken, issuedTokenType, type, expiresIn, refreshToken
            )
        }
    }
}