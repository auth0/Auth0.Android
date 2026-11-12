package com.auth0.android.embedded.authorize

import org.hamcrest.MatcherAssert.assertThat
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

        assertThat(action, `is`(NextAction.ConfirmSignup(null) as NextAction))
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
                    PasswordComplexity.CharacterType.LOWERCASE,
                    PasswordComplexity.CharacterType.UPPERCASE,
                    PasswordComplexity.CharacterType.NUMBER,
                    PasswordComplexity.CharacterType.SPECIAL
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
            `is`(listOf(PasswordComplexity.CharacterType.NUMBER, PasswordComplexity.CharacterType.SPECIAL))
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
}
