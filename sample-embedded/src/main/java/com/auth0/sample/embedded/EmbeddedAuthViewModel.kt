package com.auth0.sample.embedded

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.auth0.android.Auth0
import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.NextAction
import com.auth0.android.request.Request
import com.auth0.android.result.Credentials
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Drives the mocked embedded-authentication loop and exposes it as observable state.
 *
 * There is one method per step — [start], [identifyEmail], [challengeEmail], [verifyOtp] — each
 * wired to the button the previous step put on screen. Every call awaits one
 * `Request<Credentials, EmbeddedAuthException>`: success ends the flow with [UiState.SignedIn], a
 * continuation failure maps the server's `next` menu to the next [UiState], and any other failure is
 * terminal ([UiState.Failed]).
 *
 * Holding the client here (rather than in the Activity) keeps it — and the flow in progress — alive
 * across configuration changes: the current [UiState] simply re-renders after a rotation.
 *
 * All traffic is served by [FakeAuthorizeClient] — no live tenant is contacted.
 */
class EmbeddedAuthViewModel(application: Application) : AndroidViewModel(application) {

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

    /**
     * Awaits one request and publishes the outcome.
     *
     * The launch runs on [viewModelScope] (the main dispatcher). [Request.await] hops to
     * `Dispatchers.IO` for the network and resumes here, so the client's `transactionState` stays
     * main-thread confined — the same guarantee the callback path relied on.
     */
    private fun execute(request: Request<Credentials, EmbeddedAuthException>) {
        _uiState.value = UiState.Working
        viewModelScope.launch {
            _uiState.value = try {
                UiState.SignedIn(request.await().type)
            } catch (error: EmbeddedAuthException) {
                error.toUiState()
            }
            refreshLog()
        }
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
