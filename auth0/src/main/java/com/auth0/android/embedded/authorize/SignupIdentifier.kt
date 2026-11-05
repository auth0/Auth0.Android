package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.EmbeddedAuthClient

/**
 * An identifier the connection collects when signing up a new user, as offered on [NextAction.Signup].
 *
 * Submit it with [EmbeddedAuthClient.identify] using [type]. When [required] is `true`, it must be
 * verified before the account can be created.
 */
@ConsistentCopyVisibility
public data class SignupIdentifier internal constructor(
    public val type: IdentifierType,
    public val required: Boolean
)
