package com.auth0.sample.embedded

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.auth0.android.embedded.discovery.DiscoveryResult
import com.auth0.android.embedded.EmbeddedAuthException

@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun EmbeddedScreen(viewModel: EmbeddedViewModel = viewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var connection by rememberSaveable { mutableStateOf("") }
    val isLoading = state is DiscoveryUiState.Loading

    val runDiscovery = { viewModel.discover(connection.trim().ifBlank { null }) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.title_discovery)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary,
                ),
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 20.dp, vertical = 16.dp),
        ) {
            OutlinedTextField(
                value = connection,
                onValueChange = { connection = it },
                label = { Text(stringResource(R.string.hint_connection)) },
                singleLine = true,
                enabled = !isLoading,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { runDiscovery() }),
            )

            // Give the button some breathing room below the input.
            Spacer(Modifier.height(24.dp))

            Button(
                onClick = runDiscovery,
                enabled = !isLoading,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.status_discovering))
                } else {
                    Text(stringResource(R.string.action_discover))
                }
            }

            Spacer(Modifier.height(28.dp))

            Text(
                text = stringResource(R.string.label_result),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(8.dp))

            ResultCard(
                state = state,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )
        }
    }
}

@Composable
private fun ResultCard(state: DiscoveryUiState, modifier: Modifier = Modifier) {
    OutlinedCard(modifier = modifier) {
        val text = when (state) {
            DiscoveryUiState.Idle -> stringResource(R.string.status_idle_discovery)
            DiscoveryUiState.Loading -> stringResource(R.string.status_discovering)
            is DiscoveryUiState.Success -> formatResult(state.result)
            is DiscoveryUiState.Failure -> formatError(state.error)
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.Top,
        ) {
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

private fun formatResult(result: DiscoveryResult): String = buildString {
    appendLine("Discovery succeeded.")
    appendLine()
    appendLine("Grant types:")
    appendList(result.types.map { it.name })
    appendLine()
    appendLine("Embedded authorization supported: ${result.hasEmbeddedAuthorization}")
    appendLine()
    appendLine("Password realms:")
    appendList(result.passwordRealms)
    appendLine()
    appendLine("Passkey connections:")
    appendList(result.passkeyConnections)
    appendLine()
    appendLine("Social providers:")
    appendList(result.socialProviders)
    appendLine()
    appendLine("Passwordless OTP:")
    appendList(result.otpOptions.map { "${it.connection} (${it.type})" })
    appendLine()
    appendLine("All options (raw):")
    appendList(result.options.map { it.grantType.name })
}

private fun formatError(error: EmbeddedAuthException): String = buildString {
    appendLine("Discovery failed.")
    appendLine()
    appendLine("code:         ${error.code}")
    appendLine("description:  ${error.description}")
    appendLine("HTTP status:  ${error.statusCode}")
    appendLine("network error: ${error.isNetworkError}")
}

private fun StringBuilder.appendList(items: List<String>) {
    if (items.isEmpty()) {
        appendLine("  • (none)")
    } else {
        items.forEach { appendLine("  • $it") }
    }
}
