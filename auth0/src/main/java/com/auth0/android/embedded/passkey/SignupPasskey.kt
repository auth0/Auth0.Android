package com.auth0.android.embedded.passkey

/**
 * A passkey the connection offers to create at signup, as sent on
 * [com.auth0.android.embedded.authorize.NextAction.ConfirmSignup].
 *
 * [options] exposes the WebAuthn options. [requestJson] is the complete options object the server
 * sent, ready to use as the request JSON of a Credential Manager `CreatePublicKeyCredentialRequest`.
 */
@ConsistentCopyVisibility
public data class SignupPasskey internal constructor(
    public val options: PasskeyCreationOptions,
    public val requestJson: String
) {

    override fun toString(): String = "SignupPasskey(options=$options)"
}
