package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.EmbeddedAuthClient

/**
 * The password a connection collects when signing up a new user, as offered on [NextAction.ConfirmSignup].
 *
 * Submit it with [EmbeddedAuthClient.confirmSignup].
 */
@ConsistentCopyVisibility
public data class SignupPassword internal constructor(
    /** Whether the account can't be created without a password, unless it is created with a passkey. */
    public val required: Boolean,

    /** The advisory rules for the password. */
    public val complexity: SignupPasswordComplexity
)
