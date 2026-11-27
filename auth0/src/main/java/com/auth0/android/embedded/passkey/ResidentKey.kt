package com.auth0.android.embedded.passkey

/** Whether the new passkey must be stored on the authenticator, so the user can later sign in without naming themselves. */
public enum class ResidentKey(internal val value: String) {
    /** The authenticator should not store a discoverable credential. */
    DISCOURAGED("discouraged"),

    /** The authenticator should store a discoverable credential when it can. */
    PREFERRED("preferred"),

    /** The ceremony fails unless the authenticator stores a discoverable credential. */
    REQUIRED("required");

    internal companion object {
        fun fromValue(value: String?): ResidentKey? = entries.firstOrNull { it.value == value }
    }
}
