package com.auth0.android.embedded.passkey

/** How strongly the authenticator must verify the user during a passkey ceremony. */
public enum class UserVerification(internal val value: String) {
    /** The ceremony fails unless the authenticator verifies the user. */
    REQUIRED("required"),

    /** The authenticator verifies the user when it can. */
    PREFERRED("preferred"),

    /** The authenticator should not verify the user. */
    DISCOURAGED("discouraged");

    internal companion object {
        fun fromValue(value: String?): UserVerification? = entries.firstOrNull { it.value == value }
    }
}
