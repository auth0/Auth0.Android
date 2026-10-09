package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.EmbeddedAuthClient

/** The kind of identifier submitted to [EmbeddedAuthClient.identify]. */
public enum class IdentifierType {
    /** An email address. */
    EMAIL,
    /** A phone number. */
    PHONE,
    /** A username. */
    USERNAME,
}
