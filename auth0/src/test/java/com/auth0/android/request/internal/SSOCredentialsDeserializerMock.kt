package com.auth0.android.request.internal

import com.auth0.android.result.CredentialsMock
import com.auth0.android.result.SSOCredentials
import com.auth0.android.result.SSOCredentialsMock
import java.util.*

internal class SSOCredentialsDeserializerMock : SSOCredentialsDeserializer() {
    override fun createSSOCredentials(
        sessionTransferToken: String,
        idToken: String,
        issuedTokenType: String,
        tokenType: String,
        expiresAt: Date,
        refreshToken: String?
    ): SSOCredentials {
        return SSOCredentialsMock.create(
            sessionTransferToken, idToken, issuedTokenType, tokenType, refreshToken, expiresAt
        )
    }

    override val currentTimeInMillis: Long
        get() = CredentialsMock.CURRENT_TIME_MS
}
