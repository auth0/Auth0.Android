package com.auth0.android.embedded

import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.contains
import org.hamcrest.Matchers.containsInAnyOrder
import org.hamcrest.Matchers.empty
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.instanceOf
import org.hamcrest.Matchers.nullValue
import org.junit.Test

public class DiscoveryMapperTest {

    @Test
    public fun `password maps to the Password object`() {
        val option = Alternative(grantType = GRANT_PASSWORD).toLoginOption()

        assertThat(option, `is`<LoginOption>(LoginOption.Password))
    }

    @Test
    public fun `password-realm maps its realm onto realm and connection`() {
        val option = Alternative(grantType = GRANT_PASSWORD_REALM, realm = "db").toLoginOption()

        val realm = option as LoginOption.PasswordRealm
        assertThat(realm.realm, `is`("db"))
        assertThat(realm.connection, `is`("db"))
        assertThat(realm.grantType, `is`(GrantType.PASSWORD_REALM))
    }

    @Test
    public fun `webauthn maps its connection to a Passkey`() {
        val option = Alternative(grantType = GRANT_WEBAUTHN, connection = "passkeys").toLoginOption()

        assertThat(option, `is`(instanceOf(LoginOption.Passkey::class.java)))
        assertThat((option as LoginOption.Passkey).connection, `is`("passkeys"))
    }

    @Test
    public fun `passwordless otp reads its connection, type and identifiers`() {
        val option = Alternative(
            grantType = GRANT_PASSWORDLESS_OTP,
            connection = "email",
            type = "auth0",
            identifierTypes = listOf("email", "phone_number")
        ).toLoginOption()

        val otp = option as LoginOption.PasswordlessOtp
        assertThat(otp.connection, `is`("email"))
        assertThat(otp.type, `is`(PasswordlessType.AUTH0))
        assertThat(
            otp.identifiers,
            contains(PasswordlessIdentifier.EMAIL, PasswordlessIdentifier.PHONE_NUMBER)
        )
    }

    @Test
    public fun `passwordless otp without the auth0 type defaults to legacy`() {
        val option = Alternative(
            grantType = GRANT_PASSWORDLESS_OTP,
            connection = "sms"
        ).toLoginOption()

        assertThat((option as LoginOption.PasswordlessOtp).type, `is`(PasswordlessType.LEGACY))
    }

    @Test
    public fun `passwordless otp drops identifier types it does not recognise`() {
        val option = Alternative(
            grantType = GRANT_PASSWORDLESS_OTP,
            connection = "email",
            identifierTypes = listOf("email", "carrier_pigeon")
        ).toLoginOption()

        assertThat(
            (option as LoginOption.PasswordlessOtp).identifiers,
            contains(PasswordlessIdentifier.EMAIL)
        )
    }

    @Test
    public fun `token-exchange maps its subject token type to NativeSocial`() {
        val option = Alternative(
            grantType = GRANT_TOKEN_EXCHANGE,
            subjectTokenType = "google-id-token"
        ).toLoginOption()

        val social = option as LoginOption.NativeSocial
        assertThat(social.subjectTokenType, `is`("google-id-token"))
        assertThat(social.connection, `is`(nullValue()))
    }

    @Test
    public fun `authorization_code maps its connection and type to EmbeddedAuthorize`() {
        val option = Alternative(
            grantType = GRANT_AUTHORIZATION_CODE,
            type = "embedded_authorize",
            connection = "google"
        ).toLoginOption()

        val authorize = option as LoginOption.AuthorizationCode
        assertThat(authorize.connection, `is`("google"))
        assertThat(authorize.type, `is`("embedded_authorize"))
        assertThat(authorize.grantType, `is`(GrantType.AUTHORIZATION_CODE))
    }


    @Test
    public fun `an unrecognised grant becomes Unknown carrying the raw grant type`() {
        val option =
            Alternative(grantType = "urn:future", connection = "c").toLoginOption()

        val unknown = option as LoginOption.Unknown
        assertThat(unknown.rawGrantType, `is`("urn:future"))
        assertThat(unknown.connection, `is`("c"))
        assertThat(unknown.grantType, `is`(GrantType.UNKNOWN))
    }

    @Test
    public fun `an unknown grant falls back to realm when it has no connection`() {
        val option = Alternative(grantType = "urn:future", realm = "r").toLoginOption()

        assertThat((option as LoginOption.Unknown).connection, `is`("r"))
    }

    @Test
    public fun `an entry without a grant type is dropped`() {
        assertThat(Alternative(grantType = null).toLoginOption(), `is`(nullValue()))
    }

    @Test
    public fun `a known grant missing a required property is dropped`() {
        assertThat(Alternative(grantType = GRANT_PASSWORD_REALM).toLoginOption(), `is`(nullValue()))
        assertThat(Alternative(grantType = GRANT_WEBAUTHN).toLoginOption(), `is`(nullValue()))
        assertThat(Alternative(grantType = GRANT_PASSWORDLESS_OTP).toLoginOption(), `is`(nullValue()))
        assertThat(Alternative(grantType = GRANT_AUTHORIZATION_CODE).toLoginOption(), `is`(nullValue()))
        assertThat(Alternative(grantType = GRANT_TOKEN_EXCHANGE).toLoginOption(), `is`(nullValue()))
    }

    @Test
    public fun `toDiscoveryResult preserves the server order and drops unusable entries`() {
        val response = DiscoveryResponse(
            listOf(
                Alternative(grantType = GRANT_PASSWORD_REALM), // unusable: no realm
                Alternative(grantType = GRANT_PASSWORD),
                Alternative(grantType = GRANT_WEBAUTHN, connection = "passkeys")
            )
        )

        val options = response.toDiscoveryResult().options

        assertThat(options.map { it.grantType }, contains(GrantType.PASSWORD, GrantType.PASSKEY))
    }

    @Test
    public fun `toDiscoveryResult on no alternatives yields an empty result`() {
        val result = DiscoveryResponse(emptyList()).toDiscoveryResult()

        assertThat(result.options, `is`(empty()))
        assertThat(result.types, `is`(empty()))
    }

    @Test
    public fun `result projections group options by kind`() {
        val result = DiscoveryResponse(
            listOf(
                Alternative(grantType = GRANT_PASSWORD_REALM, realm = "db"),
                Alternative(grantType = GRANT_WEBAUTHN, connection = "passkeys"),
                Alternative(grantType = GRANT_TOKEN_EXCHANGE, subjectTokenType = "google-id-token"),
                Alternative(grantType = GRANT_PASSWORDLESS_OTP, connection = "email")
            )
        ).toDiscoveryResult()

        assertThat(result.passwordRealms, contains("db"))
        assertThat(result.passkeyConnections, contains("passkeys"))
        assertThat(result.socialProviders, contains("google-id-token"))
        assertThat(result.otpOptions.map { it.connection }, contains("email"))
        assertThat(
            result.types,
            containsInAnyOrder(
                GrantType.PASSWORD_REALM,
                GrantType.PASSKEY,
                GrantType.NATIVE_SOCIAL,
                GrantType.PASSWORDLESS_OTP
            )
        )
    }

    @Test
    public fun `hasEmbeddedAuthorize is true when authorization_code with embedded_authorize type is present`() {
        val result = DiscoveryResponse(
            listOf(
                Alternative(
                    grantType = GRANT_AUTHORIZATION_CODE,
                    type = "embedded_authorize",
                    connection = "my-db"
                )
            )
        ).toDiscoveryResult()

        assertThat(result.hasEmbeddedAuthorization, `is`(true))
    }

    @Test
    public fun `hasEmbeddedAuthorize is false when authorization_code has no type`() {
        val result = DiscoveryResponse(
            listOf(Alternative(grantType = GRANT_AUTHORIZATION_CODE, connection = "my-db"))
        ).toDiscoveryResult()

        assertThat(result.hasEmbeddedAuthorization, `is`(false))
    }

    @Test
    public fun `hasEmbeddedAuthorize is false when authorization_code has an unrecognised type`() {
        val result = DiscoveryResponse(
            listOf(
                Alternative(
                    grantType = GRANT_AUTHORIZATION_CODE,
                    type = "future_type",
                    connection = "my-db"
                )
            )
        ).toDiscoveryResult()

        assertThat(result.hasEmbeddedAuthorization, `is`(false))
    }

    @Test
    public fun `hasEmbeddedAuthorize is false when no authorization_code entry is present`() {
        val result = DiscoveryResponse(
            listOf(Alternative(grantType = GRANT_PASSWORD))
        ).toDiscoveryResult()

        assertThat(result.hasEmbeddedAuthorization, `is`(false))
    }

    @Test
    public fun `supports reflects the grant types present`() {
        val result =
            DiscoveryResponse(listOf(Alternative(grantType = GRANT_PASSWORD))).toDiscoveryResult()

        assertThat(result.supports(GrantType.PASSWORD), `is`(true))
        assertThat(result.supports(GrantType.PASSKEY), `is`(false))
    }

    private companion object {
        private const val GRANT_PASSWORD = "password"
        private const val GRANT_PASSWORD_REALM = "http://auth0.com/oauth/grant-type/password-realm"
        private const val GRANT_WEBAUTHN = "urn:okta:params:oauth:grant-type:webauthn"
        private const val GRANT_PASSWORDLESS_OTP =
            "http://auth0.com/oauth/grant-type/passwordless/otp"
        private const val GRANT_AUTHORIZATION_CODE = "authorization_code"
        private const val GRANT_TOKEN_EXCHANGE =
            "urn:ietf:params:oauth:grant-type:token-exchange"
    }
}
