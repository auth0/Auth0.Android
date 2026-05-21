package com.auth0.android.myaccount

/**
 * Represents the types of authentication methods supported by the My Account API.
 */
public enum class AuthenticationMethodType(public val type: String) {
    PASSWORD("password"),
    PASSKEY("passkey"),
    TOTP("totp"),
    PHONE("phone"),
    EMAIL("email"),
    PUSH("push-notification"),
    RECOVERY_CODE("recovery-code"),
    WEBAUTHN_PLATFORM("webauthn-platform"),
    WEBAUTHN_ROAMING("webauthn-roaming")
}