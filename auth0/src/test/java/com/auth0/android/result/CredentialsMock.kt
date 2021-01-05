package com.auth0.android.result

import java.util.*

public class CredentialsMock : Credentials {
    public constructor(
        idToken: String?,
        accessToken: String?,
        type: String?,
        refreshToken: String?,
        expiresIn: Long?
    ) : super(idToken, accessToken, type, refreshToken, expiresIn)

    public constructor(
        idToken: String?,
        accessToken: String?,
        type: String?,
        refreshToken: String?,
        expiresAt: Date?,
        scope: String?
    ) : super(idToken, accessToken, type, refreshToken, expiresAt, scope)

    override val currentTimeInMillis: Long
        get() = CURRENT_TIME_MS

    public companion object {
        @JvmField
        public val CURRENT_TIME_MS: Long = calculateCurrentTime()

        @JvmField
        public val ONE_HOUR_AHEAD_MS: Long = CURRENT_TIME_MS + 60 * 60 * 1000

        private fun calculateCurrentTime(): Long {
            val cal = Calendar.getInstance()
            cal.timeZone = TimeZone.getTimeZone("UTC")
            return cal.timeInMillis
        }
    }
}