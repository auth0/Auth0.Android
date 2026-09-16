package com.auth0.sample.embedded

import com.auth0.android.embedded.discovery.DiscoveryResult
import com.auth0.android.embedded.EmbeddedAuthException

sealed interface DiscoveryUiState {
    data object Idle : DiscoveryUiState
    data object Loading : DiscoveryUiState
    data class Success(val result: DiscoveryResult) : DiscoveryUiState
    data class Failure(val error: EmbeddedAuthException) : DiscoveryUiState
}
