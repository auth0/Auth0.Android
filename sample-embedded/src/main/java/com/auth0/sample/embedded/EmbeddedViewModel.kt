package com.auth0.sample.embedded

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.auth0.android.Auth0
import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException
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
}
