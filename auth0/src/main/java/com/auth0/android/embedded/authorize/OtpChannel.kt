package com.auth0.android.embedded.authorize

/** The channel a one-time code is delivered over, as reported on [NextAction.VerifyOtp.channel]. */
public enum class OtpChannel(public val value: String) {
    SMS("sms"),
    VOICE("voice"),
    EMAIL("email"),
    TOTP("totp");

    internal companion object {
        /** Maps the raw `channel` string to an [OtpChannel], or `null` when absent or unrecognised. */
        fun fromValue(value: String?): OtpChannel? =
            entries.firstOrNull { it.value.equals(value, ignoreCase = true) }
    }
}
