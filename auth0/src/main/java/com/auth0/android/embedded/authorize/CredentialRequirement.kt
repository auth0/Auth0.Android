package com.auth0.android.embedded.authorize

/**
 * Whether the connection collects a credential when signing up a new user, as announced on
 * [NextAction.Signup].
 */
public enum class CredentialRequirement {
    /** The connection doesn't collect this credential. */
    NONE,

    /** The credential can be set up, or skipped. */
    OPTIONAL,

    /** The account can't be created without this credential. */
    REQUIRED
}
