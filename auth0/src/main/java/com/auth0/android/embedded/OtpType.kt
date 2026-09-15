package com.auth0.android.embedded

/**
 * The kind of one-time password being verified with [EmbeddedAuthClient.verifyOtp].
 *
 * [value] is the stable wire string the `/e/authorize` contract expects on the `type` field of an
 * `action:verify:otp:v1` request.
 */
public enum class OtpType(public val value: String) {
    /**
     * An out-of-band code delivered over email, SMS, or voice. This is the type used by the
     * passwordless first-factor OTP flow.
     */
    OOB("oob"),

    /** A time-based code from an authenticator app (TOTP), used for multi-factor authentication. */
    TOTP("totp")
}
