package com.auth0.android.result

import java.util.Date

public class ApiCredentialsMock {

    public companion object {

        public fun create(
            accessToken: String,
            type: String = "Bearer",
            expiresAt: Date,
            scope: String,
        ): APICredentials {
            return APICredentials(
                accessToken, type, expiresAt, scope
            )
        }
    }
}