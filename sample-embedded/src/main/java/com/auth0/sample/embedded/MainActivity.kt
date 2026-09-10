package com.auth0.sample.embedded

import android.os.Bundle
import android.view.View
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.auth0.sample.embedded.databinding.ActivityMainBinding
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

/**
 * Renders the embedded-authentication flow owned by [EmbeddedAuthViewModel] and forwards user input.
 *
 * The Activity holds no flow logic: it collects [EmbeddedAuthViewModel.uiState] and paints each
 * [UiState], collecting [EmbeddedAuthViewModel.log] into the log view. Each state wires the action
 * button to the ViewModel call that drives the next step — so tapping the button triggers one API
 * call, and the resulting state decides what to show next.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val viewModel: EmbeddedAuthViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnRestart.setOnClickListener { viewModel.restart() }
        lifecycleScope.launch { viewModel.uiState.collect { render(it) } }
        lifecycleScope.launch { viewModel.log.collect { binding.tvLog.text = it } }
    }

    private fun render(state: UiState) {
        when (state) {
            UiState.Idle -> showIdle()
            UiState.Working -> showWorking()

            UiState.IdentifyEmail -> showInput(
                status = getString(R.string.prompt_identify),
                hintRes = R.string.hint_email,
                actionRes = R.string.action_submit_email
            ) { viewModel.identifyEmail(it) }

            UiState.ChallengeEmail -> showButton(
                status = getString(R.string.prompt_challenge),
                actionRes = R.string.action_send_code
            ) { viewModel.challengeEmail() }

            is UiState.VerifyOtp -> showInput(
                status = otpStatus(state),
                hintRes = R.string.hint_otp,
                actionRes = R.string.action_verify
            ) { viewModel.verifyOtp(it) }

            is UiState.SignedIn ->
                showFinished(getString(R.string.status_signed_in, state.credentialType))

            is UiState.Failed ->
                showFinished(getString(R.string.status_terminal, state.errorCode))
        }
    }

    /** The verify-OTP status line: a retry note if the last code was rejected, else where it was sent. */
    private fun otpStatus(state: UiState.VerifyOtp): String = when {
        state.isRetry -> getString(R.string.prompt_retry_otp)
        state.destination != null -> getString(R.string.prompt_verify, state.destination)
        else -> getString(R.string.prompt_verify_generic)
    }

    /** The initial "Start" screen. */
    private fun showIdle() {
        binding.tvStatus.setText(R.string.status_idle)
        binding.tilInput.visibility = View.GONE
        binding.btnRestart.visibility = View.GONE
        binding.btnAction.isEnabled = true
        binding.btnAction.setText(R.string.action_start)
        binding.btnAction.setOnClickListener { viewModel.start() }
    }

    /** A request is in flight: lock the action button, keep Restart available. */
    private fun showWorking() {
        binding.tvStatus.setText(R.string.status_working)
        binding.tilInput.visibility = View.GONE
        binding.btnRestart.visibility = View.VISIBLE
        binding.btnAction.isEnabled = false
    }

    /** A prompt with a text field; the button submits its contents via [onSubmit]. */
    private fun showInput(status: String, hintRes: Int, actionRes: Int, onSubmit: (String) -> Unit) {
        binding.btnRestart.visibility = View.VISIBLE
        binding.tvStatus.text = status
        binding.tilInput.visibility = View.VISIBLE
        binding.tilInput.hint = getString(hintRes)
        binding.etInput.text?.clear()
        binding.btnAction.isEnabled = true
        binding.btnAction.setText(actionRes)
        binding.btnAction.setOnClickListener { onSubmit(binding.etInput.text?.toString().orEmpty()) }
    }

    /** A prompt with just a button and no input (e.g. requesting the email challenge). */
    private fun showButton(status: String, actionRes: Int, onClick: () -> Unit) {
        binding.btnRestart.visibility = View.VISIBLE
        binding.tvStatus.text = status
        binding.tilInput.visibility = View.GONE
        binding.btnAction.isEnabled = true
        binding.btnAction.setText(actionRes)
        binding.btnAction.setOnClickListener { onClick() }
    }

    /** A terminal screen (signed in or failed): lock the action button, only Restart remains. */
    private fun showFinished(status: String) {
        binding.tvStatus.text = status
        binding.tilInput.visibility = View.GONE
        binding.btnAction.isEnabled = false
        binding.btnRestart.visibility = View.VISIBLE
    }
}
