package com.auth0.android.embedded

public class DiscoveryResult internal constructor(
    public val options: List<LoginOption>
) {

    /** Lists the unique grant-types available for a client */
    public val types: Set<GrantType> = options.mapTo(LinkedHashSet()) { it.grantType }


    /**
     * Lists the connection names supporting password-realm
     */
    public val passwordRealms: List<String> =
        options.filterIsInstance<LoginOption.PasswordRealm>().map { it.realm }

    /**
     * Lists the connection names supporting webauthn
     */
    public val passkeyConnections: List<String> =
        options.filterIsInstance<LoginOption.Passkey>().map { it.connection }

    /** One-time-code logins on offer, in the order the server returned them. */
    public val otpOptions: List<LoginOption.PasswordlessOtp> =
        options.filterIsInstance<LoginOption.PasswordlessOtp>()

    /**
     * `subject_token_type` values of the native social logins on offer, in the order the server
     * returned them. Each identifies which provider's native SDK to obtain a token from.
     */
    public val socialProviders: List<String> =
        options.filterIsInstance<LoginOption.NativeSocial>().map { it.subjectTokenType }

    /**
     *  Whether the new embedded-authorize flow is available for this client.
     *
     * `true` when the discovery response contains an `authorization_code` entry with
     * `type == "embedded_authorize"`.
     */
    public val hasEmbeddedAuthorization: Boolean =
        options.filterIsInstance<LoginOption.AuthorizationCode>()
            .any { it.type == EMBEDDED_AUTHORIZE_TYPE }

    private companion object {
        private const val EMBEDDED_AUTHORIZE_TYPE = "embedded_authorize"
    }

    /** Whether a given kind of grant-type  is supported or not. */
    public fun supports(grantType: GrantType): Boolean = grantType in types
}
