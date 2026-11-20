package com.auth0.android.embedded.authorize

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
    public fun testVerifyPasskeyDroppedWhenARequiredFieldIsMissing() {
        val complete = mapOf(
            "challenge" to "c",
            "timeout" to 1,
            "userVerification" to "preferred",
            "rpId" to "r"
        )
        for (field in complete.keys) {
            val offer = mapOf(
                ACTION_KEY to "action:verify:passkey:v1",
                "authn_params_public_key" to (complete - field)
            )
            assertThat("without $field", listOf(offer).toNextActions().isEmpty(), `is`(true))
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

    /** Parses [authnParams] the way the SDK does, so whole JSON numbers arrive as `Long`. */
    private fun passkeyOffer(authnParams: String): List<Map<String, Any>> {
        val raw: Map<String, Any> = GsonBuilder().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create().fromJson(
            """{"action":"action:verify:passkey:v1","authn_params_public_key":$authnParams}""",
            object : TypeToken<Map<String, Any>>() {}.type
        )
        return listOf(raw)
    }
}
