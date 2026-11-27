package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.passkey.AuthenticatorSelection
import com.auth0.android.embedded.passkey.PasskeyUser
import com.auth0.android.embedded.passkey.PublicKeyCredentialParameter
import com.auth0.android.embedded.passkey.RelyingParty
import com.auth0.android.embedded.passkey.ResidentKey
import com.auth0.android.embedded.passkey.UserVerification
import com.google.gson.GsonBuilder
import com.google.gson.ToNumberPolicy
import com.google.gson.reflect.TypeToken
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.instanceOf
import org.hamcrest.Matchers.nullValue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
public class NextActionMapperTest {

    private companion object {
        const val ACTION_KEY = "action"
        const val INDEX_KEY = "index"
        const val IDENTIFIER_KEY = "identifier"
        const val DELIVERY_METHODS_KEY = "delivery_methods"
        const val NAME_KEY = "name"
        const val POLL_IN_MS_KEY = "poll_in_ms"
        const val NEW_CODE_KEY = "new_code"
        const val CREATION_OPTIONS = """{"challenge":"Y3JlYXRl","rp":{"id":"login.example.com","name":"login.example.com"},"user":{"id":"dXNlci1oYW5kbGU","name":"jane@example.com","displayName":"jane@example.com"},"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required","userVerification":"preferred"},"timeout":900000}"""
    }

    @Test
    public fun testIdentifyUsernameMapped() {
        val raw = mapOf(ACTION_KEY to "action:identify:username:v1")
        val action = listOf(raw).toNextActions().first()

        assertThat(action, `is`(NextAction.IdentifyUsername))
    }

    @Test
    public fun testVerifyPasswordMapped() {
        val raw = mapOf(ACTION_KEY to "action:verify:password:v1")
        val action = listOf(raw).toNextActions().first()

        assertThat(action, `is`(NextAction.VerifyPassword))
    }

    @Test
    public fun testChallengePhoneMapped() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:phone:v1",
            INDEX_KEY to 1,
            IDENTIFIER_KEY to "+1234567890",
            DELIVERY_METHODS_KEY to listOf("text", "voice")
        )
        val action = listOf(raw).toNextActions().first()

        assertThat(action, instanceOf(NextAction.ChallengePhone::class.java))
        action as NextAction.ChallengePhone
        assertThat(action.index, `is`(1))
        assertThat(action.identifier, `is`("+1234567890"))
        assertThat(action.deliveryMethods, `is`(listOf(PhoneDeliveryMethod.TEXT, PhoneDeliveryMethod.VOICE)))
    }

    @Test
    public fun testChallengePushMapped() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:push:v1",
            INDEX_KEY to 0,
            NAME_KEY to "My Phone"
        )
        val action = listOf(raw).toNextActions().first()

        assertThat(action, instanceOf(NextAction.ChallengePush::class.java))
        action as NextAction.ChallengePush
        assertThat(action.index, `is`(0))
        assertThat(action.name, `is`("My Phone"))
    }

    @Test
    public fun testVerifyOobMapped() {
        val raw = mapOf(
            ACTION_KEY to "action:verify:oob:v1",
            POLL_IN_MS_KEY to 5000
        )
        val action = listOf(raw).toNextActions().first()

        assertThat(action, instanceOf(NextAction.VerifyOob::class.java))
        action as NextAction.VerifyOob
        assertThat(action.pollInMs, `is`(5000))
    }

    @Test
    public fun testChallengePhoneDroppedIfNoIndex() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:phone:v1",
            IDENTIFIER_KEY to "+1234567890",
            DELIVERY_METHODS_KEY to listOf("text")
            // no index — protocol violation
        )
        assertThat(listOf(raw).toNextActions().isEmpty(), `is`(true))
    }

    @Test
    public fun testChallengePhoneDroppedIfNoIdentifier() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:phone:v1",
            INDEX_KEY to 0,
            DELIVERY_METHODS_KEY to listOf("text")
            // no identifier — protocol violation
        )
        assertThat(listOf(raw).toNextActions().isEmpty(), `is`(true))
    }

    @Test
    public fun testChallengePhoneDroppedIfNoDeliveryMethods() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:phone:v1",
            INDEX_KEY to 0,
            IDENTIFIER_KEY to "+1234567890"
            // no delivery_methods — protocol violation (server contract requires it)
        )
        assertThat(listOf(raw).toNextActions().isEmpty(), `is`(true))
    }

    @Test
    public fun testChallengePushDroppedIfNoIndex() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:push:v1",
            NAME_KEY to "My Phone"
            // no index — protocol violation
        )
        assertThat(listOf(raw).toNextActions().isEmpty(), `is`(true))
    }

    @Test
    public fun testChallengePushDroppedIfNoName() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:push:v1",
            INDEX_KEY to 0
            // no name — protocol violation (server contract requires it)
        )
        assertThat(listOf(raw).toNextActions().isEmpty(), `is`(true))
    }

    @Test
    public fun testConfirmRecoveryCodeDroppedIfNoNewCode() {
        val raw = mapOf(
            ACTION_KEY to "action:confirm:recovery-code:v1"
            // no new_code — protocol violation
        )
        assertThat(listOf(raw).toNextActions().isEmpty(), `is`(true))
    }

    @Test
    public fun testVerifyOobDroppedIfNoPollInMs() {
        val raw = mapOf(
            ACTION_KEY to "action:verify:oob:v1"
            // no poll_in_ms — protocol violation
        )
        val actions = listOf(raw).toNextActions()

        assertThat(actions.isEmpty(), `is`(true))
    }

    @Test
    public fun testVerifyRecoveryCodeMapped() {
        val raw = mapOf(
            ACTION_KEY to "action:verify:recovery-code:v1"
        )
        val action = listOf(raw).toNextActions().first()

        assertThat(action, instanceOf(NextAction.VerifyRecoveryCode::class.java))
    }

    @Test
    public fun testConfirmRecoveryCodeMapped() {
        val raw = mapOf(
            ACTION_KEY to "action:confirm:recovery-code:v1",
            NEW_CODE_KEY to "NEW-CODE-123"
        )
        val action = listOf(raw).toNextActions().first()

        assertThat(action, instanceOf(NextAction.ConfirmRecoveryCode::class.java))
        action as NextAction.ConfirmRecoveryCode
        assertThat(action.newCode, `is`("NEW-CODE-123"))
    }

    @Test
    public fun testVerifyPasskeyMapped() {
        val action = passkeyOffer(
            """{"challenge":"Y2hhbGxlbmdl","timeout":900000,"userVerification":"required","rpId":"login.example.com","hints":["client-device","hybrid"],"allowCredentials":[{"type":"public-key","id":"abc","transports":["internal"]},{"type":"public-key","id":"def"}]}"""
        ).toNextActions().first()

        assertThat(action, instanceOf(NextAction.VerifyPasskey::class.java))
        action as NextAction.VerifyPasskey
        assertThat(action.capability, `is`(EmbeddedCapability.VERIFY_PASSKEY))
        assertThat(action.options.challenge, `is`("Y2hhbGxlbmdl"))
        assertThat(action.options.timeout, `is`(900000L))
        assertThat(action.options.rpId, `is`("login.example.com"))
        assertThat(action.options.userVerification, `is`(UserVerification.REQUIRED))
        assertThat(action.options.hints, `is`(listOf("client-device", "hybrid")))
        assertThat(
            action.options.allowCredentials,
            `is`(
                listOf(
                    mapOf("type" to "public-key", "id" to "abc", "transports" to listOf("internal")),
                    mapOf("type" to "public-key", "id" to "def")
                )
            )
        )
    }

    @Test
    public fun testVerifyPasskeyMapsEachUserVerificationValue() {
        val expected = mapOf(
            "required" to UserVerification.REQUIRED,
            "preferred" to UserVerification.PREFERRED,
            "discouraged" to UserVerification.DISCOURAGED
        )
        for ((value, verification) in expected) {
            val action = passkeyOffer(
                """{"challenge":"c","timeout":1,"userVerification":"$value","rpId":"r"}"""
            ).toNextActions().first() as NextAction.VerifyPasskey
            assertThat(action.options.userVerification, `is`(verification))
        }
    }

    @Test
    public fun testVerifyPasskeyHintsAndAllowCredentialsDefaultToEmpty() {
        val action = passkeyOffer(
            """{"challenge":"c","timeout":1,"userVerification":"preferred","rpId":"r"}"""
        ).toNextActions().first() as NextAction.VerifyPasskey

        assertThat(action.options.hints, `is`(emptyList()))
        assertThat(action.options.allowCredentials, `is`(emptyList()))
    }

    @Test
    public fun testVerifyPasskeyRequestJsonKeepsEveryServerFieldAndIntegers() {
        val action = passkeyOffer(
            """{"challenge":"c","timeout":900000,"userVerification":"preferred","rpId":"r","hints":["hybrid"],"allowCredentials":[{"type":"public-key","id":"abc","transports":["internal"]}],"extensions":{"credProps":true,"count":3,"ratio":1.5}}"""
        ).toNextActions().first() as NextAction.VerifyPasskey

        assertThat(
            action.requestJson,
            `is`(
                """{"challenge":"c","timeout":900000,"userVerification":"preferred","rpId":"r","hints":["hybrid"],"allowCredentials":[{"type":"public-key","id":"abc","transports":["internal"]}],"extensions":{"credProps":true,"count":3,"ratio":1.5}}"""
            )
        )
        assertThat(action.requestJson, not(containsString("900000.0")))
    }

    @Test
    public fun testVerifyPasskeyDroppedWithoutAuthnParams() {
        assertThat(listOf(mapOf(ACTION_KEY to "action:verify:passkey:v1")).toNextActions().isEmpty(), `is`(true))
        assertThat(
            listOf(mapOf(ACTION_KEY to "action:verify:passkey:v1", "authn_params_public_key" to "text")).toNextActions().isEmpty(),
            `is`(true)
        )
    }

    @Test
    public fun testVerifyPasskeyAcceptsAWholeTimeoutOfAnyNumberType() {
        for (timeout in listOf<Number>(900000, 900000L, 900000.0)) {
            val offer = mapOf(
                ACTION_KEY to "action:verify:passkey:v1",
                "authn_params_public_key" to mapOf(
                    "challenge" to "c",
                    "timeout" to timeout,
                    "userVerification" to "preferred",
                    "rpId" to "r"
                )
            )
            val action = listOf(offer).toNextActions().first() as NextAction.VerifyPasskey

            assertThat("timeout=$timeout", action.options.timeout, `is`(900000L))
        }
    }

    @Test
    public fun testVerifyPasskeyDroppedWhenARequiredFieldIsMissing() {
        val offer = passkeyOffer("""{"challenge":"c","timeout":1,"userVerification":"preferred","rpId":"r"}""").first()
        @Suppress("UNCHECKED_CAST")
        val params = offer["authn_params_public_key"] as Map<String, Any>

        assertThat(listOf(offer).toNextActions().first(), instanceOf(NextAction.VerifyPasskey::class.java))
        for (field in params.keys) {
            val incomplete = offer + ("authn_params_public_key" to (params - field))
            assertThat("without $field", listOf(incomplete).toNextActions().isEmpty(), `is`(true))
        }
    }

    @Test
    public fun testVerifyPasskeyDroppedWhenAFieldHasTheWrongType() {
        val invalid = listOf(
            """{"challenge":1,"timeout":1,"userVerification":"preferred","rpId":"r"}""",
            """{"challenge":"c","timeout":"900000","userVerification":"preferred","rpId":"r"}""",
            """{"challenge":"c","timeout":1.5,"userVerification":"preferred","rpId":"r"}""",
            """{"challenge":"c","timeout":1,"userVerification":"preferred","rpId":2}""",
            """{"challenge":"c","timeout":1,"userVerification":"always","rpId":"r"}""",
            """{"challenge":"c","timeout":1,"userVerification":1,"rpId":"r"}"""
        )
        for (params in invalid) {
            assertThat(params, passkeyOffer(params).toNextActions().isEmpty(), `is`(true))
        }
    }

    @Test
    public fun testVerifyPasskeyKeepsTheOfferWhenOptionalFieldsHaveTheWrongType() {
        val action = passkeyOffer(
            """{"challenge":"c","timeout":1,"userVerification":"preferred","rpId":"r","hints":"hybrid","allowCredentials":"abc"}"""
        ).toNextActions().first() as NextAction.VerifyPasskey

        assertThat(action.options.hints, `is`(emptyList()))
        assertThat(action.options.allowCredentials, `is`(emptyList()))
    }

    @Test
    public fun testVerifyPasskeySkipsInvalidEntriesInTheOptionalLists() {
        val action = passkeyOffer(
            """{"challenge":"c","timeout":1,"userVerification":"preferred","rpId":"r","hints":["hybrid",1,null,"client-device"],"allowCredentials":[{"id":"x"},"text",5,null,{"id":"y","extra":null}]}"""
        ).toNextActions().first() as NextAction.VerifyPasskey

        assertThat(action.options.hints, `is`(listOf("hybrid", "client-device")))
        assertThat(action.options.allowCredentials, `is`(listOf(mapOf("id" to "x"), mapOf("id" to "y"))))
    }

    @Test
    public fun testVerifyPasskeyKeepsTheOfferAndPassesOnFieldsItDoesNotModel() {
        val action = passkeyOffer(
            """{"challenge":"c","timeout":1,"userVerification":"preferred","rpId":"r","futureField":"value"}"""
        ).toNextActions().first() as NextAction.VerifyPasskey

        assertThat(action.requestJson, containsString("\"futureField\":\"value\""))
    }

    @Test
    public fun testVerifyPasskeyToStringHidesTheChallenge() {
        val action = passkeyOffer(
            """{"challenge":"SECRET-CHALLENGE","timeout":1,"userVerification":"preferred","rpId":"r"}"""
        ).toNextActions().first() as NextAction.VerifyPasskey

        assertThat(action.options.toString(), not(containsString("SECRET-CHALLENGE")))
        assertThat(action.toString(), not(containsString("SECRET-CHALLENGE")))
    }

    @Test
    public fun testSignupPasswordRequirementMapped() {
        val identifiers = mapOf("email" to mapOf("required" to true))
        val cases: List<Pair<Map<String, Any>?, CredentialRequirement>> = listOf(
            mapOf("password" to mapOf("required" to true)) to CredentialRequirement.REQUIRED,
            mapOf("password" to mapOf("required" to false)) to CredentialRequirement.OPTIONAL,
            mapOf("password" to mapOf<String, Any>()) to CredentialRequirement.NONE,
            mapOf("password" to mapOf("required" to "yes")) to CredentialRequirement.NONE,
            mapOf<String, Any>() to CredentialRequirement.NONE,
            null to CredentialRequirement.NONE
        )
        for ((methods, expected) in cases) {
            val raw = buildMap<String, Any> {
                put(ACTION_KEY, "action:signup:v1")
                put("identifiers", identifiers)
                if (methods != null) put("authentication_methods", methods)
            }
            val action = listOf(raw).toNextActions().first() as NextAction.Signup
            assertThat("authentication_methods=$methods", action.passwordRequirement, `is`(expected))
        }
    }

    @Test
    public fun testConfirmSignupWithoutPasswordOptionsHasNoPassword() {
        val action = listOf(mapOf(ACTION_KEY to "action:signup:confirm:v1")).toNextActions().first()

        assertThat(action, `is`(NextAction.ConfirmSignup(null, null) as NextAction))
    }

    @Test
    public fun testConfirmSignupPasswordComplexityMapped() {
        val raw = mapOf(
            ACTION_KEY to "action:signup:confirm:v1",
            "password_complexity_options" to mapOf(
                "min_length" to 8L,
                "character_types" to listOf("lowercase", "uppercase", "number", "special")
            )
        )
        val action = listOf(raw).toNextActions().first() as NextAction.ConfirmSignup

        val password = action.password!!
        assertThat(password.required, `is`(false))
        assertThat(password.complexity.minLength, `is`(8))
        assertThat(
            password.complexity.characterTypes,
            `is`(
                listOf(
                    SignupPasswordComplexity.CharacterType.LOWERCASE,
                    SignupPasswordComplexity.CharacterType.UPPERCASE,
                    SignupPasswordComplexity.CharacterType.NUMBER,
                    SignupPasswordComplexity.CharacterType.SPECIAL
                )
            )
        )
    }

    @Test
    public fun testConfirmSignupAcceptsAWholeMinLengthOfAnyNumberType() {
        for (minLength in listOf<Number>(8, 8L, 8.0)) {
            val raw = mapOf(
                ACTION_KEY to "action:signup:confirm:v1",
                "password_complexity_options" to mapOf("min_length" to minLength)
            )
            val action = listOf(raw).toNextActions().first() as NextAction.ConfirmSignup

            assertThat(action.password!!.complexity.minLength, `is`(8))
            assertThat(action.password!!.complexity.characterTypes, `is`(emptyList()))
        }
    }

    @Test
    public fun testConfirmSignupSkipsUnknownAndRepeatedCharacterTypes() {
        val raw = mapOf(
            ACTION_KEY to "action:signup:confirm:v1",
            "password_complexity_options" to mapOf(
                "min_length" to 8L,
                "character_types" to listOf("number", "emoji", "number", 3, "special")
            )
        )
        val action = listOf(raw).toNextActions().first() as NextAction.ConfirmSignup

        assertThat(
            action.password!!.complexity.characterTypes,
            `is`(listOf(SignupPasswordComplexity.CharacterType.NUMBER, SignupPasswordComplexity.CharacterType.SPECIAL))
        )
    }

    @Test
    public fun testConfirmSignupWithoutAValidMinLengthHasNoPassword() {
        val invalid = listOf<Any?>(null, 0L, -1L, 8.5, "8", 3_000_000_000L)
        for (minLength in invalid) {
            val options = if (minLength == null) mapOf("character_types" to listOf("number")) else mapOf("min_length" to minLength)
            val raw = mapOf(ACTION_KEY to "action:signup:confirm:v1", "password_complexity_options" to options)
            val action = listOf(raw).toNextActions().first() as NextAction.ConfirmSignup

            assertThat("min_length=$minLength", action.password, `is`(nullValue()))
        }
    }

    @Test
    public fun testSignupPasskeyRequirementIsOptionalWhenOffered() {
        val action = signupOffer("""{"password":{"required":true},"passkey":{"required":false}}""")

        assertThat(action.passkeyRequirement, `is`(CredentialRequirement.OPTIONAL))
        assertThat(action.passwordRequirement, `is`(CredentialRequirement.REQUIRED))
    }

    @Test
    public fun testSignupPasskeyRequirementIsNoneWithoutAuthenticationMethods() {
        val raw = mapOf(ACTION_KEY to "action:signup:v1", "identifiers" to mapOf("email" to mapOf("required" to true)))

        assertThat((listOf(raw).toNextActions().first() as NextAction.Signup).passkeyRequirement, `is`(CredentialRequirement.NONE))
    }

    @Test
    public fun testSignupPasskeyRequirementIsNoneWhenOnlyAPasswordIsOffered() {
        val action = signupOffer("""{"password":{"required":false}}""")

        assertThat(action.passkeyRequirement, `is`(CredentialRequirement.NONE))
        assertThat(action.passwordRequirement, `is`(CredentialRequirement.OPTIONAL))
    }

    @Test
    public fun testSignupPasskeyRequirementIsNoneWhenRequiredIsNotABoolean() {
        assertThat(signupOffer("""{"passkey":{"required":"yes"}}""").passkeyRequirement, `is`(CredentialRequirement.NONE))
    }

    @Test
    public fun testSignupPasskeyRequirementIsNoneWhenRequiredIsMissing() {
        assertThat(signupOffer("""{"passkey":{}}""").passkeyRequirement, `is`(CredentialRequirement.NONE))
    }

    @Test
    public fun testSignupPasskeyRequirementIsRequiredWhenTheServerSaysSo() {
        assertThat(signupOffer("""{"passkey":{"required":true}}""").passkeyRequirement, `is`(CredentialRequirement.REQUIRED))
    }

    @Test
    public fun testConfirmSignupPasskeyMapped() {
        val action = confirmOffer("""{"authn_params_public_key":$CREATION_OPTIONS}""")

        val passkey = action.passkey!!
        assertThat(passkey.options.challenge, `is`("Y3JlYXRl"))
        assertThat(passkey.options.timeout, `is`(900000L))
        assertThat(passkey.options.rp, `is`(RelyingParty("login.example.com", "login.example.com")))
        assertThat(passkey.options.user, `is`(PasskeyUser("dXNlci1oYW5kbGU", "jane@example.com", "jane@example.com")))
        assertThat(
            passkey.options.pubKeyCredParams,
            `is`(listOf(PublicKeyCredentialParameter("public-key", -8), PublicKeyCredentialParameter("public-key", -7)))
        )
        assertThat(
            passkey.options.authenticatorSelection,
            `is`(AuthenticatorSelection(ResidentKey.REQUIRED, UserVerification.PREFERRED))
        )
        assertThat(action.password, `is`(nullValue()))
    }

    @Test
    public fun testConfirmSignupPasskeyRequestJsonKeepsEveryServerFieldAndIntegers() {
        val action = confirmOffer("""{"authn_params_public_key":$CREATION_OPTIONS}""")

        val json = action.passkey!!.requestJson
        assertThat(json, containsString("\"timeout\":900000"))
        assertThat(json, containsString("\"alg\":-7"))
        assertThat(json, not(containsString("900000.0")))
        assertThat(json, not(containsString("-7.0")))
        assertThat(json, containsString("\"displayName\":\"jane@example.com\""))
    }

    @Test
    public fun testConfirmSignupWithoutPasskeyOptionsHasNoPasskey() {
        assertThat(confirmOffer("""{}""").passkey, `is`(nullValue()))
    }

    @Test
    public fun testConfirmSignupKeepsThePasswordAndThePasskeyTogether() {
        val action = confirmOffer(
            """{"password_complexity_options":{"min_length":8},"authn_params_public_key":$CREATION_OPTIONS}"""
        )

        assertThat(action.password!!.complexity.minLength, `is`(8))
        assertThat(action.passkey!!.options.challenge, `is`("Y3JlYXRl"))
    }

    @Test
    public fun testConfirmSignupPasskeyIsNullWhenARequiredFieldIsMissing() {
        for (field in listOf("challenge", "timeout", "rp", "user", "pubKeyCredParams", "authenticatorSelection")) {
            val options = creationOptions().apply { remove(field) }

            val action = confirmOffer(mapOf("authn_params_public_key" to options))

            assertThat("without $field", action.passkey, `is`(nullValue()))
        }
    }

    @Test
    public fun testConfirmSignupPasskeyIsNullWhenAFieldOfANestedObjectIsMissing() {
        val nested = mapOf("rp" to "name", "user" to "displayName")
        for ((key, field) in nested) {
            val options = creationOptions()
            options[key] = (options[key] as Map<*, *>).filterKeys { it != field }

            val action = confirmOffer(mapOf("authn_params_public_key" to options))

            assertThat("$key without $field", action.passkey, `is`(nullValue()))
        }
    }

    @Test
    public fun testConfirmSignupPasskeyIsNullWhenAFieldHasTheWrongType() {
        val wrong = mapOf<String, Any>(
            "challenge" to 1L,
            "timeout" to "900000",
            "rp" to "login.example.com",
            "user" to listOf("jane"),
            "pubKeyCredParams" to "public-key",
            "authenticatorSelection" to "required"
        )
        for ((field, value) in wrong) {
            val options = creationOptions().apply { put(field, value) }

            val action = confirmOffer(mapOf("authn_params_public_key" to options))

            assertThat("$field = $value", action.passkey, `is`(nullValue()))
        }
    }

    @Test
    public fun testConfirmSignupPasskeyIsNullWhenTheTimeoutIsNotAWholeNumber() {
        val options = creationOptions().apply { put("timeout", 1.5) }

        assertThat(confirmOffer(mapOf("authn_params_public_key" to options)).passkey, `is`(nullValue()))
    }

    @Test
    public fun testConfirmSignupPasskeyAcceptsAWholeTimeoutOfAnyNumberType() {
        for (timeout in listOf<Number>(900000, 900000L, 900000.0)) {
            val options = creationOptions().apply { put("timeout", timeout) }

            val action = confirmOffer(mapOf("authn_params_public_key" to options))

            assertThat("timeout=$timeout", action.passkey!!.options.timeout, `is`(900000L))
        }
    }

    @Test
    public fun testConfirmSignupPasskeySkipsUnknownAlgorithmEntries() {
        val options = creationOptions().apply {
            put(
                "pubKeyCredParams",
                listOf(
                    mapOf("type" to "other", "alg" to -7L),
                    mapOf("type" to "public-key", "alg" to "ES256"),
                    mapOf("type" to "public-key", "alg" to -7.5),
                    mapOf("type" to "public-key"),
                    mapOf("type" to "public-key", "alg" to -257L)
                )
            )
        }

        val action = confirmOffer(mapOf("authn_params_public_key" to options))

        assertThat(action.passkey!!.options.pubKeyCredParams, `is`(listOf(PublicKeyCredentialParameter("public-key", -257))))
    }

    @Test
    public fun testConfirmSignupPasskeyIsNullWhenNoAlgorithmEntryIsValid() {
        val options = creationOptions().apply { put("pubKeyCredParams", listOf(mapOf("type" to "other", "alg" to -7L))) }

        assertThat(confirmOffer(mapOf("authn_params_public_key" to options)).passkey, `is`(nullValue()))
    }

    @Test
    public fun testConfirmSignupPasskeyAuthenticatorSelectionFieldsAreOptional() {
        val options = creationOptions().apply { put("authenticatorSelection", emptyMap<String, Any>()) }

        val selection = confirmOffer(mapOf("authn_params_public_key" to options)).passkey!!.options.authenticatorSelection

        assertThat(selection, `is`(AuthenticatorSelection(null, null)))
    }

    @Test
    public fun testConfirmSignupPasskeyAuthenticatorSelectionIgnoresUnknownValues() {
        val options = creationOptions().apply {
            put("authenticatorSelection", mapOf("residentKey" to "always", "userVerification" to "sometimes"))
        }

        val selection = confirmOffer(mapOf("authn_params_public_key" to options)).passkey!!.options.authenticatorSelection

        assertThat(selection, `is`(AuthenticatorSelection(null, null)))
    }

    @Test
    public fun testConfirmSignupPasskeyKeepsTheOfferAndPassesOnFieldsItDoesNotModel() {
        val options = creationOptions().apply { put("futureField", "value") }

        val action = confirmOffer(mapOf("authn_params_public_key" to options))

        assertThat(action.passkey!!.requestJson, containsString("\"futureField\":\"value\""))
    }

    @Test
    public fun testConfirmSignupPasskeyToStringHidesTheChallengeAndTheUser() {
        val action = confirmOffer("""{"authn_params_public_key":$CREATION_OPTIONS}""")

        for (text in listOf(action.passkey!!.toString(), action.passkey!!.options.toString(), action.toString())) {
            assertThat(text, not(containsString("Y3JlYXRl")))
            assertThat(text, not(containsString("jane@example.com")))
            assertThat(text, not(containsString("dXNlci1oYW5kbGU")))
        }
    }

    /** Parses [authnParams] the way the SDK does, so whole JSON numbers arrive as `Long`. */
    private fun passkeyOffer(authnParams: String): List<Map<String, Any>> {
        val raw: Map<String, Any> = GsonBuilder().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create().fromJson(
            """{"action":"action:verify:passkey:v1","authn_params_public_key":$authnParams}""",
            object : TypeToken<Map<String, Any>>() {}.type
        )
        return listOf(raw)
    }

    private fun signupOffer(authenticationMethods: String): NextAction.Signup {
        val raw: Map<String, Any> = parse(
            """{"action":"action:signup:v1","identifiers":{"email":{"required":true}},"authentication_methods":$authenticationMethods}"""
        )
        return listOf(raw).toNextActions().first() as NextAction.Signup
    }

    private fun confirmOffer(fields: String): NextAction.ConfirmSignup = confirmOffer(parse(fields))

    private fun confirmOffer(fields: Map<String, Any>): NextAction.ConfirmSignup =
        listOf(mapOf<String, Any>(ACTION_KEY to "action:signup:confirm:v1") + fields).toNextActions().first() as NextAction.ConfirmSignup

    private fun creationOptions(): MutableMap<String, Any> = parse(CREATION_OPTIONS).toMutableMap()

    private fun parse(json: String): Map<String, Any> =
        GsonBuilder().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create().fromJson(
            json,
            object : TypeToken<Map<String, Any>>() {}.type
        )
}
