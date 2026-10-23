package com.auth0.sample.embedded

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.auth0.android.Auth0
import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthError
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.authorize.IdentifierType
import com.auth0.android.embedded.authorize.NextAction
import com.auth0.android.embedded.authorize.OtpType
import com.auth0.android.embedded.authorize.PhoneDeliveryMethod
import com.auth0.android.request.DefaultClient
import com.auth0.android.result.Credentials
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class EmbeddedViewModel(application: Application) : AndroidViewModel(application) {

    private val client: EmbeddedAuthClient by lazy {
        EmbeddedAuthClient(
            Auth0.getInstance(
                application.getString(R.string.com_auth0_client_id),
                application.getString(R.string.com_auth0_domain)
            ).apply {
                networkingClient = DefaultClient.Builder()
                    .enableLogging(true)
                    .build()
            }
        )
    }

    /** Defaults to the tenant's Management API; swap for your own API identifier. */
    private val defaultAudience: String =
        "https://${application.getString(R.string.com_auth0_domain)}/api/v2/"

    // region Authorize (/e/authorize) — the interactive multi-step flow.

    private val _authorizeState = MutableStateFlow<AuthorizeUiState>(AuthorizeUiState.Idle)
    val authorizeState: StateFlow<AuthorizeUiState> = _authorizeState.asStateFlow()

    /** Kicks off the flow. Completes via a continuation (see [runStep]). */
    fun startAuthorize(connection: String): Unit = runStep {
        client.authorize(connection, audience = defaultAudience).await()
    }

    fun identifyEmail(email: String): Unit = runStep { client.identify(email, IdentifierType.EMAIL).await() }

    fun challengeEmail(index: Int): Unit = runStep { client.challengeEmail(index).await() }

    fun identifyPhone(phone: String): Unit = runStep { client.identify(phone, IdentifierType.PHONE).await() }

    fun identifyUsername(username: String): Unit =
        runStep { client.identify(username, IdentifierType.USERNAME).await() }

    fun challengePhone(index: Int, deliveryMethod: PhoneDeliveryMethod): Unit =
        runStep { client.challengePhone(index, deliveryMethod).await() }

    fun challengePush(index: Int): Unit = runStep { client.challengePush(index).await() }

    /** Continuation: the server always answers with a [NextAction.ConfirmRecoveryCode] carrying the rotated code. */
    fun verifyRecoveryCode(code: String): Unit = runStep { client.verifyRecoveryCode(code).await() }

    /** Terminal step: on success this yields [Credentials][com.auth0.android.result.Credentials]. */
    fun verifyOtp(code: String, type: OtpType): Unit = runTerminalStep { client.verifyOtp(code, type).await() }

    /** Terminal step: yields credentials, or continues if the server requires a second factor. */
    fun verifyPassword(password: String): Unit = runTerminalStep { client.verifyPassword(password).await() }

    /** Terminal step: acknowledges the rotated recovery code. */
    fun confirmRecoveryCode(): Unit = runTerminalStep { client.confirmRecoveryCode().await() }

    /**
     * Polls for push approval. The SDK performs one poll per call, so the app owns the loop: wait the
     * server-advertised `pollInMs` between polls, and give up on a terminal error. The flow is
     * sequential, so every other step stops polling first via [stopPolling].
     */
    fun verifyPush(initialPollInMs: Int) {
        pollJob?.cancel()
        val offered = (_authorizeState.value as? AuthorizeUiState.ActionsAvailable)?.actions.orEmpty()
        _authorizeState.value = AuthorizeUiState.Polling(offered.filterNot { it is NextAction.VerifyOob })
        pollJob = viewModelScope.launch {
            var delayMs = initialPollInMs.toLong()
            while (true) {
                delay(delayMs)
                try {
                    _authorizeState.value = AuthorizeUiState.Authenticated(
                        withContext(NonCancellable) { client.verifyOob().await() }
                    )
                    return@launch
                } catch (error: EmbeddedAuthException) {
                    val pending = error.error as? EmbeddedAuthError.InsufficientAuthorization
                    val reason = pending?.reason
                    if (reason != EmbeddedAuthError.InsufficientAuthorization.Reason.AUTHORIZATION_PENDING &&
                        reason != EmbeddedAuthError.InsufficientAuthorization.Reason.SLOW_DOWN
                    ) {
                        _authorizeState.value = error.toAuthorizeState()
                        return@launch
                    }
                    delayMs = pending.nextActions.filterIsInstance<NextAction.VerifyOob>()
                        .firstOrNull()?.pollInMs?.toLong() ?: delayMs
                    _authorizeState.value =
                        AuthorizeUiState.Polling(pending.nextActions.filterNot { it is NextAction.VerifyOob })
                }
            }
        }
    }

    fun resetAuthorize() {
        viewModelScope.launch {
            stopPolling()
            _authorizeState.value = AuthorizeUiState.Idle
        }
    }

    private var pollJob: Job? = null

    /**
     * Stops the push-polling loop between polls. A cancel during the wait takes effect immediately;
     * a poll already in flight completes first, so the SDK keeps the session it returned.
     */
    private suspend fun stopPolling() {
        pollJob?.cancelAndJoin()
        pollJob = null
    }

    private fun runTerminalStep(step: suspend () -> Credentials) {
        viewModelScope.launch {
            stopPolling()
            if (_authorizeState.value is AuthorizeUiState.Authenticated) return@launch
            _authorizeState.value = AuthorizeUiState.Loading
            _authorizeState.value = try {
                AuthorizeUiState.Authenticated(step())
            } catch (error: EmbeddedAuthException) {
                error.toAuthorizeState()
            }
        }
    }

    /**
     * Runs a non-terminal step. These steps never resolve successfully — the server drives the
     * flow forward by responding with `403 insufficient_authorization` carrying the next actions,
     * which the SDK surfaces as an [EmbeddedAuthException]. A plain success here is unexpected.
     */
    private fun runStep(step: suspend () -> Unit) {
        viewModelScope.launch {
            stopPolling()
            if (_authorizeState.value is AuthorizeUiState.Authenticated) return@launch
            _authorizeState.value = AuthorizeUiState.Loading
            _authorizeState.value = try {
                step()
                AuthorizeUiState.Message("Step completed without a continuation.")
            } catch (error: EmbeddedAuthException) {
                error.toAuthorizeState()
            }
        }
    }

    private fun EmbeddedAuthException.toAuthorizeState(): AuthorizeUiState =
        when (val e = error) {
            is EmbeddedAuthError.InsufficientAuthorization ->
                if (e.nextActions.isNotEmpty()) AuthorizeUiState.ActionsAvailable(e.nextActions)
                else AuthorizeUiState.Failed(this)
            else -> AuthorizeUiState.Failed(this)
        }

    // endregion
}
