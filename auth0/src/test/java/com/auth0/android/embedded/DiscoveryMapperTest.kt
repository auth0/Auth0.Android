package com.auth0.android.embedded

import com.google.gson.Gson
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.contains
import org.hamcrest.Matchers.empty
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.instanceOf
import org.junit.Test

public class DiscoveryMapperTest {

    private val gson = Gson()

    private fun map(json: String): List<LoginOption> =
        gson.fromJson(json, DiscoveryResponse::class.java).toDiscoveryResult().options

    @Test
    public fun `maps password grant to the Password option`() {
        val options = map("""{"alternatives":[{"grant_type":"password"}]}""")
        assertThat(options, contains(LoginOption.Password))
    }

    @Test
    public fun `maps password-realm grant to a PasswordRealm option`() {
        val options = map(
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/password-realm","realm":"my-db"}]}"""
        )
        assertThat(options, contains(LoginOption.PasswordRealm(realm = "my-db")))
    }

    @Test
    public fun `maps webauthn grant to a Passkey option`() {
        val options = map(
            """{"alternatives":[{"grant_type":"urn:okta:params:oauth:grant-type:webauthn","connection":"my-db"}]}"""
        )
        assertThat(options, contains(LoginOption.Passkey(connection = "my-db")))
    }

    @Test
    public fun `maps legacy passwordless otp to the LEGACY variant`() {
        val options = map(
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/passwordless/otp","type":"legacy","connection":"email","identifier_types":["email"]}]}"""
        )
        assertThat(
            options, contains(
                LoginOption.PasswordlessOtp(
                    connection = "email",
                    identifiers = setOf(PasswordlessIdentifier.EMAIL),
                    type = PasswordlessType.LEGACY
                )
            )
        )
    }

    @Test
    public fun `maps database passwordless otp to the DATABASE variant`() {
        val options = map(
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/passwordless/otp","type":"auth0","connection":"my-db","identifier_types":["email","phone_number"]}]}"""
        )
        assertThat(
            options, contains(
                LoginOption.PasswordlessOtp(
                    connection = "my-db",
                    identifiers = setOf(PasswordlessIdentifier.EMAIL, PasswordlessIdentifier.PHONE_NUMBER),
                    type = PasswordlessType.AUTH0
                )
            )
        )
    }

    @Test
    public fun `maps authorization code grant to an EmbeddedAuthorize option`() {
        val options = map(
            """{"alternatives":[{"grant_type":"authorization_code","type":"embedded_authorize","connection":"my-db"}]}"""
        )
        assertThat(options, contains(LoginOption.EmbeddedAuthorize(connection = "my-db")))
    }

    @Test
    public fun `carries each token exchange subject token type verbatim`() {
        val options = map(
            """{"alternatives":[
              {"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_type":"http://auth0.com/oauth/token-type/google-id-token"},
              {"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_type":"http://auth0.com/oauth/token-type/apple-authz-code"},
              {"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_type":"http://auth0.com/oauth/token-type/facebook-info-session-access-token"}
            ]}"""
        )
        assertThat(
            options, contains(
                LoginOption.NativeSocial("http://auth0.com/oauth/token-type/google-id-token"),
                LoginOption.NativeSocial("http://auth0.com/oauth/token-type/apple-authz-code"),
                LoginOption.NativeSocial("http://auth0.com/oauth/token-type/facebook-info-session-access-token")
            )
        )
    }

    @Test
    public fun `reports an unmodelled grant type as Unknown rather than dropping it`() {
        val options = map("""{"alternatives":[{"grant_type":"future_grant","connection":"my-db"}]}""")
        assertThat(
            options,
            contains(LoginOption.Unknown(rawGrantType = "future_grant", connection = "my-db"))
        )
    }

    @Test
    public fun `carries an unmodelled subject token type verbatim`() {
        val options = map(
            """{"alternatives":[{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_type":"http://auth0.com/oauth/token-type/future-token"}]}"""
        )
        assertThat(
            options,
            contains(LoginOption.NativeSocial("http://auth0.com/oauth/token-type/future-token"))
        )
    }

    @Test
    public fun `treats an unmodelled otp type as the legacy variant`() {
        val options = map(
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/passwordless/otp","type":"future_type","connection":"my-db","identifier_types":["email"]}]}"""
        )
        assertThat((options.single() as LoginOption.PasswordlessOtp).type, equalTo(PasswordlessType.LEGACY))
    }

    @Test
    public fun `ignores an unmodelled identifier type but keeps the rest`() {
        val options = map(
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/passwordless/otp","type":"auth0","connection":"my-db","identifier_types":["email","fax"]}]}"""
        )
        assertThat(
            (options.single() as LoginOption.PasswordlessOtp).identifiers,
            equalTo(setOf(PasswordlessIdentifier.EMAIL))
        )
    }

    @Test
    public fun `does not let one unusable entry discard the others`() {
        val options = map(
            """{"alternatives":[
              {"grant_type":"urn:okta:params:oauth:grant-type:webauthn"},
              {"grant_type":"password"}
            ]}"""
        )
        assertThat(options, contains(LoginOption.Password))
    }

    @Test
    public fun `skips an entry that names no grant type`() {
        assertThat(map("""{"alternatives":[{"connection":"my-db"}]}"""), empty())
    }

    @Test
    public fun `skips a password-realm entry with no realm`() {
        val json =
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/password-realm"}]}"""
        assertThat(map(json), empty())
    }

    @Test
    public fun `skips a passkey entry with no connection`() {
        val json = """{"alternatives":[{"grant_type":"urn:okta:params:oauth:grant-type:webauthn"}]}"""
        assertThat(map(json), empty())
    }

    @Test
    public fun `skips an otp entry with no connection`() {
        val json =
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/passwordless/otp","type":"auth0","identifier_types":["email"]}]}"""
        assertThat(map(json), empty())
    }

    @Test
    public fun `skips an embedded authorize entry with no connection`() {
        val json = """{"alternatives":[{"grant_type":"authorization_code","type":"embedded_authorize"}]}"""
        assertThat(map(json), empty())
    }

    @Test
    public fun `skips a token exchange entry with no subject token type`() {
        val json = """{"alternatives":[{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange"}]}"""
        assertThat(map(json), empty())
    }

    @Test
    public fun `maps an otp entry with no identifier types to an empty identifier set`() {
        val json =
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/passwordless/otp","type":"auth0","connection":"my-db"}]}"""
        assertThat((map(json).single() as LoginOption.PasswordlessOtp).identifiers, empty())
    }

    @Test
    public fun `maps an empty alternatives array to an empty result`() {
        assertThat(map("""{"alternatives":[]}"""), empty())
    }

    @Test
    public fun `maps a missing alternatives array to an empty result`() {
        assertThat(map("""{}"""), empty())
    }

    @Test
    public fun `preserves the order the server sent`() {
        val result = gson.fromJson(FakeDiscoveryData.SUCCESS_RESPONSE, DiscoveryResponse::class.java)
            .toDiscoveryResult()
        assertThat(
            result.options.map { it.grantType }, equalTo(
                listOf(
                    GrantType.AUTHORIZATION_CODE,
                    GrantType.NATIVE_SOCIAL,
                    GrantType.PASSWORD,
                    GrantType.PASSKEY,
                    GrantType.PASSWORDLESS_OTP,
                    GrantType.PASSWORDLESS_OTP,
                    GrantType.PASSWORD_REALM
                )
            )
        )
    }

    @Test
    public fun `collapses the available kinds of login into types`() {
        val result = gson.fromJson(FakeDiscoveryData.SUCCESS_RESPONSE, DiscoveryResponse::class.java)
            .toDiscoveryResult()
        assertThat(
            result.types, equalTo(
                setOf(
                    GrantType.AUTHORIZATION_CODE,
                    GrantType.NATIVE_SOCIAL,
                    GrantType.PASSWORD,
                    GrantType.PASSKEY,
                    GrantType.PASSWORDLESS_OTP,
                    GrantType.PASSWORD_REALM
                )
            )
        )
    }

    @Test
    public fun `projects the e-authorize pipeline options into capabilities`() {
        val result = gson.fromJson(FakeDiscoveryData.SUCCESS_RESPONSE, DiscoveryResponse::class.java)
            .toDiscoveryResult()
        assertThat(result.capabilities.map { it.grantType }, equalTo(listOf(GrantType.AUTHORIZATION_CODE)))
        assertThat(result.capabilities.single(), instanceOf(LoginOption.EmbeddedAuthorize::class.java))
    }

    @Test
    public fun `exposes no capabilities when only direct grants are advertised`() {
        val result = gson.fromJson("""{"alternatives":[{"grant_type":"password"}]}""", DiscoveryResponse::class.java)
            .toDiscoveryResult()
        assertThat(result.capabilities, empty())
    }

    @Test
    public fun `exposes the connection on the base type so options can be grouped`() {
        val result = gson.fromJson(FakeDiscoveryData.SUCCESS_RESPONSE, DiscoveryResponse::class.java)
            .toDiscoveryResult()
        val byConnection = result.options.groupBy { it.connection }
        assertThat(
            byConnection["Username-Password-Authentication"]?.map { it.grantType }, equalTo(
                listOf(
                    GrantType.PASSKEY,
                    GrantType.PASSWORDLESS_OTP,
                    GrantType.PASSWORD_REALM
                )
            )
        )
    }

    @Test
    public fun `reports both password grants separately when a tenant advertises both`() {
        val options = map(
            """{"alternatives":[
              {"grant_type":"password"},
              {"grant_type":"http://auth0.com/oauth/grant-type/password-realm","realm":"my-db"}
            ]}"""
        )
        assertThat(
            options,
            contains(LoginOption.Password, LoginOption.PasswordRealm(realm = "my-db"))
        )
    }

    @Test
    public fun `distinguishes the two password grants by type`() {
        val result = gson.fromJson(
            """{"alternatives":[
              {"grant_type":"password"},
              {"grant_type":"http://auth0.com/oauth/grant-type/password-realm","realm":"my-db"}
            ]}""",
            DiscoveryResponse::class.java
        ).toDiscoveryResult()
        assertThat(
            result.types,
            equalTo(setOf(GrantType.PASSWORD, GrantType.PASSWORD_REALM))
        )
    }

    @Test
    public fun `advertises password-realm without the plain password grant`() {
        // A tenant with no default directory. Checking for PASSWORD alone would miss password login.
        val result = gson.fromJson(
            """{"alternatives":[{"grant_type":"http://auth0.com/oauth/grant-type/password-realm","realm":"my-db"}]}""",
            DiscoveryResponse::class.java
        ).toDiscoveryResult()
        assertThat(result.types, equalTo(setOf(GrantType.PASSWORD_REALM)))
    }

    @Test
    public fun `groups password-realm under its realm while plain password stays unkeyed`() {
        val result = gson.fromJson(
            """{"alternatives":[
              {"grant_type":"password"},
              {"grant_type":"http://auth0.com/oauth/grant-type/password-realm","realm":"my-db"}
            ]}""",
            DiscoveryResponse::class.java
        ).toDiscoveryResult()
        val byConnection = result.options.groupBy { it.connection }
        assertThat(byConnection[null], contains(LoginOption.Password))
        assertThat(byConnection["my-db"], contains(LoginOption.PasswordRealm(realm = "my-db")))
    }

    @Test
    public fun `maps every variant of the canned payload`() {
        val options = map(FakeDiscoveryData.SUCCESS_RESPONSE)
        assertThat(options.size, equalTo(7))
        assertThat(options[0], instanceOf(LoginOption.EmbeddedAuthorize::class.java))
        assertThat(options[1], instanceOf(LoginOption.NativeSocial::class.java))
        assertThat(options[2], equalTo(LoginOption.Password))
        assertThat(options[3], instanceOf(LoginOption.Passkey::class.java))
        assertThat(
            options[4], equalTo(
                LoginOption.PasswordlessOtp(
                    connection = "Username-Password-Authentication",
                    identifiers = setOf(PasswordlessIdentifier.EMAIL, PasswordlessIdentifier.PHONE_NUMBER),
                    type = PasswordlessType.AUTH0
                )
            )
        )
        assertThat(
            options[5], equalTo(
                LoginOption.PasswordlessOtp(
                    connection = "email",
                    identifiers = setOf(PasswordlessIdentifier.EMAIL),
                    type = PasswordlessType.LEGACY
                )
            )
        )
        assertThat(
            options[6],
            equalTo(LoginOption.PasswordRealm(realm = "Username-Password-Authentication"))
        )
    }
}
