package com.auth0.android.embedded.authorize

import org.hamcrest.MatcherAssert.assertThat
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
    public fun testChallengePushDroppedIfNoIndex() {
        val raw = mapOf(
            ACTION_KEY to "action:challenge:push:v1",
            NAME_KEY to "My Phone"
            // no index — protocol violation
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
}
