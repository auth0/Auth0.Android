package com.auth0.android.embedded

/**
 * Translates the `GET /e/discovery` wire payload into the public [DiscoveryResult].
 *
 * An entry the SDK does not recognise becomes [LoginOption.Unknown] rather than being dropped, and
 * no single entry can fail the whole response.
 */
internal fun DiscoveryResponse.toDiscoveryResult(): DiscoveryResult =
    DiscoveryResult(alternatives.orEmpty().mapNotNull { it.toLoginOption() })

/**
 * Maps one wire entry to its [LoginOption], or `null` if it named no grant type or omitted a
 * property its variant needs to be usable.
 */
internal fun Alternative.toLoginOption(): LoginOption? {
    val grantType = grantType ?: return null
    return when (grantType) {
        GRANT_PASSWORD -> LoginOption.Password

        GRANT_PASSWORD_REALM -> realm?.let { LoginOption.PasswordRealm(realm = it) }

        GRANT_WEBAUTHN -> connection?.let { LoginOption.Passkey(connection = it) }

        GRANT_PASSWORDLESS_OTP -> connection?.let {
            LoginOption.PasswordlessOtp(
                connection = it,
                identifiers = identifierTypes.toOtpIdentifiers(),
                type = if (type == TYPE_AUTH0) PasswordlessType.AUTH0 else PasswordlessType.LEGACY
            )
        }

        GRANT_AUTHORIZATION_CODE -> connection?.let { LoginOption.EmbeddedAuthorize(connection = it) }

        GRANT_TOKEN_EXCHANGE -> subjectTokenType?.let {
            LoginOption.NativeSocial(subjectTokenType = it)
        }

        else -> LoginOption.Unknown(rawGrantType = grantType, connection = connection ?: realm)
    }
}

private fun List<String>?.toOtpIdentifiers(): Set<PasswordlessIdentifier> =
    orEmpty().mapNotNullTo(LinkedHashSet()) {
        when (it) {
            IDENTIFIER_EMAIL -> PasswordlessIdentifier.EMAIL
            IDENTIFIER_PHONE_NUMBER -> PasswordlessIdentifier.PHONE_NUMBER
            else -> null
        }
    }

private const val GRANT_PASSWORD = "password"
private const val GRANT_PASSWORD_REALM = "http://auth0.com/oauth/grant-type/password-realm"
private const val GRANT_WEBAUTHN = "urn:okta:params:oauth:grant-type:webauthn"
private const val GRANT_PASSWORDLESS_OTP = "http://auth0.com/oauth/grant-type/passwordless/otp"
private const val GRANT_AUTHORIZATION_CODE = "authorization_code"
private const val GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

private const val TYPE_AUTH0 = "auth0"

private const val IDENTIFIER_EMAIL = "email"
private const val IDENTIFIER_PHONE_NUMBER = "phone_number"
