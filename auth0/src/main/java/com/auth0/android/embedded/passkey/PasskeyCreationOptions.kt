package com.auth0.android.embedded.passkey

/**
 * The options the server offers for creating a passkey at signup, as sent on [SignupPasskey].
 */
@ConsistentCopyVisibility
public data class PasskeyCreationOptions internal constructor(
    /** The base64url-encoded challenge the authenticator signs. Use it for one attempt only. */
    public val challenge: String,

    /** How long, in milliseconds, the ceremony may take. */
    public val timeout: Long,

    /** The relying party the passkey is scoped to. */
    public val rp: RelyingParty,

    /** The user the passkey is created for. */
    public val user: PasskeyUser,

    /** The public key algorithms the server accepts, in order of preference. Never empty. */
    public val pubKeyCredParams: List<PublicKeyCredentialParameter>,

    /** What the server asks of the authenticator. */
    public val authenticatorSelection: AuthenticatorSelection
) {

    override fun toString(): String =
        "PasskeyCreationOptions(challenge='xxxxx', timeout=$timeout, rp=$rp, user=$user, " +
                "pubKeyCredParams=$pubKeyCredParams, authenticatorSelection=$authenticatorSelection)"
}

/** The relying party a new passkey is scoped to. */
@ConsistentCopyVisibility
public data class RelyingParty internal constructor(
    /** The relying party identifier. */
    public val id: String,

    /** The name shown to the user. */
    public val name: String
)

/** The user a new passkey is created for. */
@ConsistentCopyVisibility
public data class PasskeyUser internal constructor(
    /** The base64url-encoded user handle. */
    public val id: String,

    /** The account name. */
    public val name: String,

    /** The name shown to the user. */
    public val displayName: String
) {

    override fun toString(): String = "PasskeyUser(id='xxxxx', name='xxxxx', displayName='xxxxx')"
}

/** A public key algorithm the server accepts for a new passkey. */
@ConsistentCopyVisibility
public data class PublicKeyCredentialParameter internal constructor(
    /** The credential type. Always `public-key`. */
    public val type: String,

    /** The COSE algorithm identifier, for example `-7` for ES256. */
    public val alg: Int
)

/** What the server asks of the authenticator that creates the passkey. */
@ConsistentCopyVisibility
public data class AuthenticatorSelection internal constructor(
    /** Whether the passkey must be discoverable. `null` when the server sent none. */
    public val residentKey: ResidentKey?,

    /** Whether the authenticator must verify the user. `null` when the server sent none. */
    public val userVerification: UserVerification?
)
