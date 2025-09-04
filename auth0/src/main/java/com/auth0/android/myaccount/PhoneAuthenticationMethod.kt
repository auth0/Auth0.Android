package com.auth0.android.myaccount

/**
 * Represents the preferred method for phone-based multi-factor authentication, either "sms" or "voice".
 * This is used when enrolling a new phone factor or updating an existing one.
 */
public enum class PhoneAuthenticationMethodType(public val value: String) {
    SMS("sms"),
    VOICE("voice")
}