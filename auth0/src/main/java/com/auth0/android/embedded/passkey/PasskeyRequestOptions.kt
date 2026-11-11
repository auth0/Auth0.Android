package com.auth0.android.embedded.passkey

/**
 * The options the server offers for a passkey sign-in, as sent on [NextAction.VerifyPasskey].
 */
@ConsistentCopyVisibility
public data class PasskeyRequestOptions internal constructor(
    /** The single-use, base64url-encoded challenge the authenticator signs. */
    public val challenge: String,

    /** How long, in milliseconds, the ceremony may take. */
    public val timeout: Long,

    /** The relying party identifier the passkey is scoped to. */
    public val rpId: String,

    /** Whether the authenticator must verify the user. */
    public val userVerification: UserVerification,

    /** Hints about which kind of authenticator to prefer, in order. Empty when the server sent none. */
    public val hints: List<String>,

    /**
     * The credentials the server restricts the ceremony to, each as the server sent it. Empty when the
     * server sent none. The API doesn't define an entry's fields, so they are not modelled here.
     */
    public val allowCredentials: List<Map<String, Any>>
) {

    override fun toString(): String =
        "PasskeyRequestOptions(challenge='xxxxx', timeout=$timeout, rpId='$rpId', " +
                "userVerification=$userVerification, hints=$hints, allowCredentials=${allowCredentials.size} entries)"
}
