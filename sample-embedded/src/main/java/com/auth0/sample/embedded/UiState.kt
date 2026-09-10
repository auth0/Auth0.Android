package com.auth0.sample.embedded

/**
 * What the screen should show at one point in the embedded-authentication flow.
 *
 * [EmbeddedAuthViewModel] publishes one of these after every step; the Activity paints it and wires
 * the on-screen button to the matching ViewModel call. Because the ViewModel survives configuration
 * changes, the current state (e.g. an OTP prompt) is preserved across rotation for free.
 */
sealed interface UiState {

    /** The initial screen: a single "Start" button, nothing in flight. */
    data object Idle : UiState

    /** A request is on the wire; the action button is disabled until it returns. */
    data object Working : UiState

    /** Ask for an email address; the button calls [EmbeddedAuthViewModel.identifyEmail]. */
    data object IdentifyEmail : UiState

    /** Offer to send an email code; the button calls [EmbeddedAuthViewModel.challengeEmail]. */
    data object ChallengeEmail : UiState

    /**
     * Ask for the one-time code; the button calls [EmbeddedAuthViewModel.verifyOtp].
     *
     * @param destination where the code was sent, when the server reports it.
     * @param isRetry `true` when the previous code was rejected, so the prompt can say so.
     */
    data class VerifyOtp(val destination: String?, val isRetry: Boolean) : UiState

    /** Terminal success: the flow produced credentials of [credentialType]. */
    data class SignedIn(val credentialType: String) : UiState

    /** Terminal failure carrying the server [errorCode]; only Restart remains usable. */
    data class Failed(val errorCode: String) : UiState
}
