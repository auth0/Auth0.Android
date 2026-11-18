package com.auth0.android.embedded.authorize

/**
 * Advisory rules for a signup password: the minimum length and the character types that are all required.
 *
 * The server applies the connection's full password policy, which can include rules not listed here,
 * such as requiring only some of the character types. A password that meets these rules can still be
 * rejected with [com.auth0.android.embedded.EmbeddedAuthError.InsufficientAuthorization.Reason.INVALID_PASSWORD].
 */
@ConsistentCopyVisibility
public data class PasswordComplexity internal constructor(
    /** The minimum length, in UTF-16 code units. */
    public val minLength: Int,

    /** The character types the password must contain, all of them. Empty when none is required. */
    public val characterTypes: List<CharacterType>
) {

    /** A kind of character a password can be required to contain. */
    public enum class CharacterType {
        LOWERCASE,
        UPPERCASE,
        NUMBER,
        SPECIAL
    }
}
