package com.auth0.android.embedded

/**
 * What a client can currently use to log a user in, as reported by the embedded discovery endpoint.
 *
 * @param options every login available, in the order the server returned them — which is a
 * reasonable default order to render. An empty list is a valid result: it means this client has
 * nothing enabled, not that the call failed.
 */
public class DiscoveryResult internal constructor(
    public val options: List<LoginOption>
) {

    /** The kinds of grant-types available. */
    public val types: Set<GrantType> = options.mapTo(LinkedHashSet()) { it.grantType }


    /** Realm names of the password-realm logins on offer, in the order the server returned them. */
    public val passwordRealms: List<String> =
        options.filterIsInstance<LoginOption.PasswordRealm>().map { it.realm }

    /** Connections holding a passkey credential, in the order the server returned them. */
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

    /** Whether a given kind of login is available. */
    public fun supports(grantType: GrantType): Boolean = grantType in types
}
