package com.auth0.android.embedded.authorize

/** A single step in the embedded authentication flow. [value] is the raw string used by `/e/authorize`. */
public enum class EmbeddedAction(public val value: String) {
    IDENTIFY_EMAIL("action:identify:email:v1"),
    IDENTIFY_PHONE("action:identify:phone:v1"),
    CHALLENGE_EMAIL("action:challenge:email:v1"),
    VERIFY_OTP("action:verify:otp:v1"),
    UNKNOWN("Unknown");

    internal companion object {
        fun fromValue(value: String): EmbeddedAction =
            entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}
