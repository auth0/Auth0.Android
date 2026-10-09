package com.auth0.android.authentication

/**
 * Delivery channel for a phone-number OTP during passkey signup identifier verification.
 *
 * Maps to the `delivery_method` request parameter of `POST /passkey/register`. [TEXT] sends the
 * one-time code via SMS (the server default); [VOICE] delivers it through a voice call. Only applies
 * when the connection requires phone identifier verification. If the requested channel is not enabled
 * on the connection, the server responds with an `invalid_request` error.
 *
 * @property value the wire value sent to the server.
 */
public enum class PasskeyDeliveryMethod(public val value: String) {
    /** Deliver the one-time code via SMS. */
    TEXT("text"),

    /** Deliver the one-time code via a voice call. */
    VOICE("voice")
}
