package com.auth0.android.embedded

/**
 * What a client can currently use to log a user in, as reported by the embedded discovery endpoint.
 *
 * There are two ways to read this. Ask which kinds of login exist:
 *
 * ```
 * if (GrantType.PASSKEY in result.types) showPasskeyButton()
 * result.socialProviders.forEach { showSocialButton(it) }
 * ```
 *
 * Or walk the options, which also gives you what each one needs in order to be acted on:
 *
 * ```
 * result.options.forEach { option -> render(option) }
 * ```
 *
 * @param options every login available, in the order the server returned them — which is a
 * reasonable default order to render. An empty list is a valid result: it means this client has
 * nothing enabled, not that the call failed.
 */
public class DiscoveryResult internal constructor(
    public val options: List<LoginOption>
) {

    /** The kinds of login available. */
    public val types: Set<GrantType> = options.mapTo(LinkedHashSet()) { it.grantType }

    /** Native social providers to offer, in the order the server returned them. */
    public val socialProviders: List<SocialProvider> =
        options.filterIsInstance<LoginOption.NativeSocial>().map { it.provider }

    /** Whether a given kind of login is available. */
    public fun supports(grantType: GrantType): Boolean = grantType in types
}
