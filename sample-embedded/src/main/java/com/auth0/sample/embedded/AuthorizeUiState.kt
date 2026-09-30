package com.auth0.sample.embedded

import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.authorize.NextAction
import com.auth0.android.result.Credentials

/** State of the multi-step embedded `/e/authorize` flow driven by [EmbeddedViewModel]. */
sealed interface AuthorizeUiState {

    /** No flow in progress. */
    data object Idle : AuthorizeUiState

    /** A call is in flight. */
    data object Loading : AuthorizeUiState

    /** The server returned a continuation: these are the steps the user can take next. */
    data class ActionsAvailable(val actions: List<NextAction>) : AuthorizeUiState

    /** Terminal success: [verifyOtp][EmbeddedAuthClient.verifyOtp] yielded credentials. */
    data class Authenticated(val credentials: Credentials) : AuthorizeUiState

    /** Terminal failure (access denied, too many attempts, network error, …). */
    data class Failed(val error: EmbeddedAuthException) : AuthorizeUiState

    /** An unexpected non-continuation outcome, shown for diagnostics. */
    data class Message(val text: String) : AuthorizeUiState
}
