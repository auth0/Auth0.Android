package com.auth0.android.embedded

/**
 * The kinds of login a client can perform. One value per grant type the discovery endpoint reports.
 */
public enum class GrantType {
    PASSWORD,

    PASSWORD_REALM,

    PASSKEY,

    PASSWORDLESS_OTP,


    NATIVE_SOCIAL,


    AUTHORIZATION_CODE,

    /** A login this version of the SDK does not model. See [LoginOption.Unknown]. */
    UNKNOWN
}

/**
 *
 * Switch on the subtype:
 *
 * ```
 * when (option) {
 *     is LoginOption.Password -> addPasswordForm(realm = null)
 *     is LoginOption.PasswordRealm -> addPasswordForm(realm = option.realm)
 *     is LoginOption.Passkey -> addPasskeyButton(option.connection)
 *     is LoginOption.PasswordlessOtp -> option.identifiers.forEach { addOtpButton(it) }
 *     is LoginOption.NativeSocial -> addSocialButton(option.provider)
 *     is LoginOption.EmbeddedAuthorize -> addContinueButton(option.connection)
 *     is LoginOption.Unknown -> Unit
 * }
 * ```
 *
 *
 */
public sealed interface LoginOption {

    public val grantType: GrantType

    /**
     * Connection this option authenticates against, or `null` when the server resolves it — the
     * case for a password login against the tenant's default directory, and for native social.
     */
    public val connection: String?

    /**
     * Username and password login against the tenant's default directory.
     *
     * Carries no connection: the server resolves it from the tenant's default directory and the
     * client never sends one. Log in with `AuthenticationAPIClient.login(email, password)`.
     *
     * See [PasswordRealm] for the same login against a named realm. A tenant can advertise both.
     */
    public object Password : LoginOption {
        override val connection: String? = null
        override val grantType: GrantType = GrantType.PASSWORD
    }

    /**
     * Username and password login against a named realm.
     *
     * Log in with `AuthenticationAPIClient.login(email, password, realm)`.
     *
     */
    public data class PasswordRealm internal constructor(
        public val realm: String
    ) : LoginOption {
        override val connection: String = realm
        override val grantType: GrantType = GrantType.PASSWORD_REALM
    }

    /**
     * Passkey login.
     *
     * @param connection connection holding the credential.
     */
    public data class Passkey internal constructor(
        override val connection: String
    ) : LoginOption {
        override val grantType: GrantType = GrantType.PASSKEY
    }

    /**
     * Login with a one-time code.
     *
     * @param connection connection to challenge.
     * @param identifiers what the connection accepts. Offer one entry point per identifier — a
     * connection accepting both is two ways to sign in, not one.
     * @param type which challenge call this connection needs, and which parameters the token
     * exchange then takes. See [PasswordlessType].
     */
    public data class PasswordlessOtp internal constructor(
        override val connection: String,
        public val identifiers: Set<PasswordlessIdentifier>,
        public val type: PasswordlessType
    ) : LoginOption {
        override val grantType: GrantType = GrantType.PASSWORDLESS_OTP
    }

    /**
     * Login by exchanging a token obtained from a social provider's own native SDK.
     *
     * @param provider the provider to obtain the token from.
     */
    public data class NativeSocial internal constructor(
        public val provider: SocialProvider
    ) : LoginOption {
        override val connection: String? = null
        override val grantType: GrantType = GrantType.NATIVE_SOCIAL
    }

    /**
     * Interactive login through the embedded authorize endpoint.
     *
     * @param connection connection to authenticate against.
     */
    public data class EmbeddedAuthorize internal constructor(
        override val connection: String
    ) : LoginOption {
        override val grantType: GrantType = GrantType.AUTHORIZATION_CODE
    }

    /**
     * A login the server advertised that this version of the SDK does not model. Reported rather than
     * dropped, so the result stays a truthful account of what the server said.
     *
     * @param rawGrantType the `grant_type` the server sent.
     * @param connection connection the server sent, if any.
     */
    public data class Unknown internal constructor(
        public val rawGrantType: String,
        override val connection: String?
    ) : LoginOption {
        override val grantType: GrantType = GrantType.UNKNOWN
    }
}

/**
 * An identifier a passwordless connection accepts for a one-time code.
 */
public enum class PasswordlessIdentifier {
    EMAIL,
    PHONE_NUMBER
}

/**
 * Which passwordless flow a connection uses.
 *
 * The two need different challenge calls and take mutually exclusive parameters on the token
 * exchange, so this is what decides how to act on a [LoginOption.PasswordlessOtp].
 */
public enum class PasswordlessType {
    /** Legacy passwordless, on an email or SMS connection. */
    LEGACY,

    /** Passwordless on a database connection. */
    AUTH0
}

/**
 * A social provider whose native SDK can supply a token to exchange for credentials.
 */
public enum class SocialProvider {
    GOOGLE,
    APPLE,
    FACEBOOK,

    /** A provider this version of the SDK does not model. */
    UNKNOWN
}
