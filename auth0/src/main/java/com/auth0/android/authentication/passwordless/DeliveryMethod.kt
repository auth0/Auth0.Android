package com.auth0.android.authentication.passwordless

/**
 * Delivery method for a phone-number OTP challenge.
 *
 * Maps to the `delivery_method` request parameter of `POST /otp/challenge`. [TEXT] sends the
 * one-time code via SMS (the server default); [VOICE] delivers it through a voice call.
 *
 * @property value the wire value sent to the server.
 */
public enum class DeliveryMethod(public val value: String) {
    /** Deliver the one-time code via SMS. */
    TEXT("text"),

    /** Deliver the one-time code via a voice call. */
    VOICE("voice")
}
