package com.auth0.sample.embedded

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.auth0.android.Auth0
import com.auth0.android.callback.Callback
import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.NextAction
import com.auth0.android.result.Credentials
import com.auth0.sample.embedded.databinding.ActivityMainBinding

/**
 * Drives the mocked embedded-authentication loop end to end.
 *
 * Each [EmbeddedAuthClient] call returns a `Request<Credentials, EmbeddedAuthException>`. A step that
 * does not finish the flow fails with `insufficient_authorization`, whose `next` menu tells us which
 * method to call next; we render the matching input and button. The flow ends when a call succeeds
 * with [Credentials] or fails with any other error.
 *
 * All traffic is served by [FakeAuthorizeClient] — no live tenant is contacted.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val fake = FakeAuthorizeClient()

    private val client: EmbeddedAuthClient by lazy {
        val auth0 = Auth0.getInstance(
            "EMBEDDED_SAMPLE_CLIENT_ID",
            getString(R.string.com_auth0_domain)
        )
        auth0.networkingClient = fake
        EmbeddedAuthClient(auth0)
    }

    private val callback = object : Callback<Credentials, EmbeddedAuthException> {
        override fun onSuccess(result: Credentials) = onSignedIn(result)
        override fun onFailure(error: EmbeddedAuthException) = onStep(error)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        showStart()
        binding.btnRestart.setOnClickListener { showStart() }
    }

    /** Resets the UI to the initial "Start" state, abandoning any flow in progress. */
    private fun showStart() {
        binding.tvStatus.setText(R.string.status_idle)
        binding.tilInput.visibility = View.GONE
        binding.btnRestart.visibility = View.GONE
        binding.btnAction.isEnabled = true
        binding.btnAction.setText(R.string.action_start)
        fake.clearLog()
        binding.tvLog.text = ""
        binding.btnAction.setOnClickListener {
            binding.tvStatus.text = getString(R.string.status_working)
            client.authorize().start(callback)
        }
    }

    /**
     * Renders the next step from the server's continuation menu, or a terminal error.
     *
     * We switch on the first offered [NextAction] rather than on [EmbeddedAuthException.description]:
     * per the spec the progression responses omit `error_description`, so `description` would just be
     * the SDK's generic fallback on every step. `error_description` is only populated on recoverable or
     * terminal outcomes (e.g. the wrong-code retry surfaces `invalid_identifier_or_code`).
     */
    private fun onStep(error: EmbeddedAuthException) {
        binding.btnRestart.visibility = View.VISIBLE
        renderLog()
        when (val action = error.nextActions.firstOrNull()) {
            is NextAction.IdentifyEmail -> {
                binding.tvStatus.setText(R.string.prompt_identify)
                promptForInput(R.string.hint_email, R.string.action_submit_email) { value ->
                    client.identifyEmail(value).start(callback)
                }
            }

            is NextAction.ChallengeEmail -> {
                binding.tvStatus.setText(R.string.prompt_challenge)
                promptForButton(R.string.action_send_code) { client.challengeEmail().start(callback) }
            }

            is NextAction.VerifyOtp -> {
                binding.tvStatus.text = verifyPrompt(error, action)
                promptForInput(R.string.hint_otp, R.string.action_verify) { value ->
                    client.verifyOtp(value).start(callback)
                }
            }

            else -> {
                // IdentifyPhone / Unknown, or no menu at all — treat as terminal for this demo.
                binding.tvStatus.text = getString(R.string.status_terminal, error.code)
                showTerminal()
            }
        }
    }

    /** The verify-OTP prompt: a retry note if the last code was rejected, else where the code was sent. */
    private fun verifyPrompt(error: EmbeddedAuthException, action: NextAction.VerifyOtp): String {
        if (error.description == INVALID_CODE) return getString(R.string.prompt_retry_otp)
        val destination = action.identifier
        return if (destination != null) {
            getString(R.string.prompt_verify, destination)
        } else {
            getString(R.string.prompt_verify_generic)
        }
    }

    /** Shows a text field and an action button that submits its contents. */
    private fun promptForInput(hintRes: Int, actionRes: Int, submit: (String) -> Unit) {
        binding.tilInput.visibility = View.VISIBLE
        binding.tilInput.hint = getString(hintRes)
        binding.etInput.text?.clear()
        binding.btnAction.isEnabled = true
        binding.btnAction.setText(actionRes)
        binding.btnAction.setOnClickListener {
            binding.tvStatus.setText(R.string.status_working)
            submit(binding.etInput.text?.toString().orEmpty())
        }
    }

    /** Shows a single action button with no input (e.g. requesting an email challenge). */
    private fun promptForButton(actionRes: Int, submit: () -> Unit) {
        binding.tilInput.visibility = View.GONE
        binding.btnAction.isEnabled = true
        binding.btnAction.setText(actionRes)
        binding.btnAction.setOnClickListener {
            binding.tvStatus.setText(R.string.status_working)
            submit()
        }
    }

    private fun onSignedIn(credentials: Credentials) {
        binding.tvStatus.text = getString(R.string.status_signed_in, credentials.type)
        renderLog()
        showTerminal()
    }

    /** Locks the action button; only Restart remains usable. */
    private fun showTerminal() {
        binding.tilInput.visibility = View.GONE
        binding.btnAction.isEnabled = false
        binding.btnRestart.visibility = View.VISIBLE
    }

    /** Dumps every response the mock has served so far, newest step last. */
    private fun renderLog() {
        binding.tvLog.text = fake.log.mapIndexed { index, exchange ->
            "#${index + 1}  POST ${exchange.endpoint} → ${exchange.statusCode}\n" +
                redactTokens(exchange.body)
        }.joinToString("\n\n")
    }

    /**
     * Replaces token values with a placeholder before display. The mock's tokens are throwaway
     * fixtures, but the project rule is to never surface token values — so we honour it here too.
     */
    private fun redactTokens(body: String): String =
        TOKEN_FIELD.replace(body) { "\"${it.groupValues[1]}\":\"«redacted»\"" }

    private companion object {
        /** The spec's `error_description` for a rejected code / unknown user; surfaced as-is by the SDK. */
        private const val INVALID_CODE = "invalid_identifier_or_code"

        private val TOKEN_FIELD =
            Regex("\"(access_token|refresh_token|id_token)\"\\s*:\\s*\"[^\"]*\"")
    }
}
