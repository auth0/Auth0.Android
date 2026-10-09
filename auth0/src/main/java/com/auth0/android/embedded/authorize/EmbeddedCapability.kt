package com.auth0.android.embedded.authorize

/** A single step in the embedded authentication flow. [value] is the raw string used by `/e/authorize`. */
public enum class EmbeddedCapability(public val value: String) {
    IDENTIFY_EMAIL("action:identify:email:v1"),
    IDENTIFY_PHONE("action:identify:phone:v1"),
    IDENTIFY_USERNAME("action:identify:username:v1"),
    CHALLENGE_EMAIL("action:challenge:email:v1"),
    CHALLENGE_PHONE("action:challenge:phone:v1"),
    CHALLENGE_PUSH("action:challenge:push:v1"),
    VERIFY_OTP("action:verify:otp:v1"),
    VERIFY_PASSWORD("action:verify:password:v1"),
    VERIFY_OOB("action:verify:oob:v1"),
    VERIFY_RECOVERY_CODE("action:verify:recovery-code:v1"),
    CONFIRM_RECOVERY_CODE("action:confirm:recovery-code:v1"),
    UNKNOWN("Unknown");

    internal companion object {
        fun fromValue(value: String): EmbeddedCapability =
            entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}
