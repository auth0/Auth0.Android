package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.EmbeddedAuthClient

/** The kind of one-time password verified with [EmbeddedAuthClient.verifyOtp]. */
public enum class OtpType(public val value: String) {
    /** An out-of-band code delivered over email, SMS, or voice. */
    OOB("oob"),

    /** A time-based code from an authenticator app (TOTP). */
    TOTP("totp")
}
