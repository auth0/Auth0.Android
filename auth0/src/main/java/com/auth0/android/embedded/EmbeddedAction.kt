package com.auth0.android.embedded

/**
 * A single step in the embedded-authentication loop.
 *
 * The same value plays two roles: the SDK advertises the actions it supports as *capabilities* on
 * the first `/e/authorize` call, and the server echoes them back inside [NextAction] to say what may
 * happen next. [value] is the stable wire string the `/e/authorize` contract uses.
 */
public enum class EmbeddedAction(public val value: String) {
    IDENTIFY_EMAIL("action:identify:email:v1"),
    IDENTIFY_PHONE("action:identify:phone:v1"),
    CHALLENGE_EMAIL("action:challenge:email:v1"),
    VERIFY_OTP("action:verify:otp:v1"),

    /** An action this version of the SDK does not model. See [NextAction.Unknown]. */
    UNKNOWN("Unknown");

    internal companion object {
        fun fromValue(value: String): EmbeddedAction =
            entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}
