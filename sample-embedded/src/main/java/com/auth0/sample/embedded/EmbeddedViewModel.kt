package com.auth0.sample.embedded

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.auth0.android.Auth0
import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.authorize.OtpType
import com.auth0.android.request.DefaultClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

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

    // region Discovery (/e/discovery) — retained for reference; not shown in the UI.

    private val _uiState = MutableStateFlow<DiscoveryUiState>(DiscoveryUiState.Idle)
    val uiState: StateFlow<DiscoveryUiState> = _uiState.asStateFlow()

    fun discover(connection: String? = null) {
        _uiState.value = DiscoveryUiState.Loading
        viewModelScope.launch {
            _uiState.value = try {
                DiscoveryUiState.Success(client.discover(connection).await())
            } catch (error: EmbeddedAuthException) {
                DiscoveryUiState.Failure(error)
            }
        }
    }

    // endregion

    // region Authorize (/e/authorize) — the interactive multi-step flow.

    private val _authorizeState = MutableStateFlow<AuthorizeUiState>(AuthorizeUiState.Idle)
    val authorizeState: StateFlow<AuthorizeUiState> = _authorizeState.asStateFlow()

    /** Kicks off the flow. Completes via a continuation (see [runStep]). */
    fun startAuthorize(connection: String): Unit = runStep { client.authorize(connection).await() }

    fun identifyEmail(email: String): Unit = runStep { client.identifyEmail(email).await() }

    fun identifyPhone(phone: String): Unit = runStep { client.identifyPhone(phone).await() }

    fun challengeEmail(index: Int): Unit = runStep { client.challengeEmail(index).await() }

    /** Terminal step: on success this yields [Credentials][com.auth0.android.result.Credentials]. */
    fun verifyOtp(code: String, type: OtpType): Unit {
        _authorizeState.value = AuthorizeUiState.Loading
        viewModelScope.launch {
            _authorizeState.value = try {
                AuthorizeUiState.Authenticated(client.verifyOtp(code, type).await())
            } catch (error: EmbeddedAuthException) {
                error.toAuthorizeState()
            }
        }
    }

    fun resetAuthorize() {
        _authorizeState.value = AuthorizeUiState.Idle
    }

    /**
     * Runs a non-terminal step. These steps never resolve successfully — the server drives the
     * flow forward by responding with `403 insufficient_authorization` carrying the next actions,
     * which the SDK surfaces as an [EmbeddedAuthException]. A plain success here is unexpected.
     */
    private fun runStep(step: suspend () -> Unit) {
        _authorizeState.value = AuthorizeUiState.Loading
        viewModelScope.launch {
            _authorizeState.value = try {
                step()
                AuthorizeUiState.Message("Step completed without a continuation.")
            } catch (error: EmbeddedAuthException) {
                error.toAuthorizeState()
            }
        }
    }

    private fun EmbeddedAuthException.toAuthorizeState(): AuthorizeUiState =
        if (isInsufficientAuthorization && nextActions.isNotEmpty()) {
            AuthorizeUiState.ActionsAvailable(nextActions)
        } else {
            AuthorizeUiState.Failed(this)
        }

    // endregion
}
