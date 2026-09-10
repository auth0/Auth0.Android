package com.auth0.sample.embedded

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.auth0.android.Auth0
import com.auth0.android.callback.Callback
import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.NextAction
import com.auth0.android.request.Request
import com.auth0.android.result.Credentials
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The callback-based twin of [EmbeddedAuthViewModel]: same public surface, same [UiState] output, but
 * each step is driven with [Request.start] and a [Callback] instead of a suspending `await()`.
 *
 * Both view models are interchangeable — the Activity swaps one for the other by changing the type it
 * asks `by viewModels()` for; nothing else in the Activity changes. The step logic is duplicated on
 * purpose so each file reads as a complete example of its style, side by side.
 *
 * The SDK delivers [Callback.onSuccess] / [Callback.onFailure] on the main thread, so the state
 * updates here need no dispatching.
 *
 * All traffic is served by [FakeAuthorizeClient] — no live tenant is contacted.
 */
class EmbeddedAuthCallbackViewModel(application: Application) : AndroidViewModel(application) {

    private val fake = FakeAuthorizeClient()

    private val client: EmbeddedAuthClient = EmbeddedAuthClient(
        Auth0.getInstance(
            "EMBEDDED_SAMPLE_CLIENT_ID",
            application.getString(R.string.com_auth0_domain)
        ).apply { networkingClient = fake }
    )

    private val _uiState = MutableStateFlow<UiState>(UiState.Idle)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val _log = MutableStateFlow("")
    val log: StateFlow<String> = _log.asStateFlow()

    /** Handles the outcome of every step; reused across calls since it does not depend on the request. */
    private val callback = object : Callback<Credentials, EmbeddedAuthException> {
        override fun onSuccess(result: Credentials) {
            _uiState.value = UiState.SignedIn(result.type)
            refreshLog()
        }

        override fun onFailure(error: EmbeddedAuthException) {
            _uiState.value = error.toUiState()
            refreshLog()
        }
    }

    /** Begins a fresh flow from a clean log. */
    fun start() {
        fake.clearLog()
        _log.value = ""
        execute(client.authorize())
    }

    fun identifyEmail(email: String): Unit = execute(client.identifyEmail(email))

    fun challengeEmail(): Unit = execute(client.challengeEmail())

    fun verifyOtp(code: String): Unit = execute(client.verifyOtp(code))

    /** Returns to the initial screen. */
    fun restart() {
        fake.clearLog()
        _log.value = ""
        _uiState.value = UiState.Idle
    }

    /** Fires one request and lets [callback] publish the outcome. */
    private fun execute(request: Request<Credentials, EmbeddedAuthException>) {
        _uiState.value = UiState.Working
        request.start(callback)
    }

    /**
     * Maps a continuation failure to the next state.
     *
     * We switch on the first offered [NextAction] rather than on [EmbeddedAuthException.description]:
     * per the spec the progression responses omit `error_description`, so `description` would be the
     * SDK's generic fallback on every step. It is populated only on the OTP retry, which we surface
     * via [UiState.VerifyOtp.isRetry].
     */
    private fun EmbeddedAuthException.toUiState(): UiState =
        when (val action = nextActions.firstOrNull()) {
            is NextAction.IdentifyEmail -> UiState.IdentifyEmail
            is NextAction.ChallengeEmail -> UiState.ChallengeEmail
            is NextAction.VerifyOtp -> UiState.VerifyOtp(
                destination = action.identifier,
                isRetry = description == INVALID_CODE
            )
            // IdentifyPhone / Unknown, or no menu at all — terminal for this demo.
            else -> UiState.Failed(code)
        }

    /** Republishes the mock's request log, newest step last, with token values redacted. */
    private fun refreshLog() {
        _log.value = fake.log.mapIndexed { index, exchange ->
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
