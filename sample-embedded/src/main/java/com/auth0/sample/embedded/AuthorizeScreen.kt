package com.auth0.sample.embedded

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
import androidx.compose.material3.TextButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.authorize.NextAction
import com.auth0.android.embedded.authorize.OtpType
import com.auth0.android.result.Credentials

@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun AuthorizeScreen(
    viewModel: EmbeddedViewModel = viewModel(),
    initialConnection: String,
    onBack: () -> Unit = {},
) {
    val state by viewModel.authorizeState.collectAsStateWithLifecycle()
    var connection by rememberSaveable { mutableStateOf(initialConnection) }
    val isLoading = state is AuthorizeUiState.Loading
    val isIdle = state is AuthorizeUiState.Idle

    val canStart = isIdle && connection.isNotBlank()
    val startAuthorize = { viewModel.startAuthorize(connection.trim()) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.title_screen)) },
                navigationIcon = {
                    TextButton(onClick = onBack) {
                        Text(
                            text = "← Back",
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                    }
                },
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
                .padding(horizontal = 20.dp, vertical = 16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            OutlinedTextField(
                value = connection,
                onValueChange = { connection = it },
                label = { Text(stringResource(R.string.hint_connection_required)) },
                singleLine = true,
                enabled = isIdle,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { if (canStart) startAuthorize() }),
            )

            Spacer(Modifier.height(24.dp))

            Button(
                onClick = startAuthorize,
                enabled = canStart,
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
                    Text(stringResource(R.string.status_authorizing))
                } else {
                    Text(stringResource(R.string.action_start_authorize))
                }
            }

            Spacer(Modifier.height(28.dp))

            when (val current = state) {
                AuthorizeUiState.Idle -> InfoCard(stringResource(R.string.status_idle_authorize))
                AuthorizeUiState.Loading -> InfoCard(stringResource(R.string.status_authorizing))
                is AuthorizeUiState.ActionsAvailable -> ActionsSection(current.actions, viewModel)
                is AuthorizeUiState.Authenticated -> InfoCard(formatCredentials(current.credentials))
                is AuthorizeUiState.Failed -> InfoCard(formatError(current.error))
                is AuthorizeUiState.Message -> InfoCard(current.text)
            }

            if (!isIdle && !isLoading) {
                Spacer(Modifier.height(20.dp))
                OutlinedButton(
                    onClick = { viewModel.resetAuthorize() },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.action_start_over))
                }
            }
        }
    }
}

@Composable
private fun ActionsSection(actions: List<NextAction>, viewModel: EmbeddedViewModel) {
    Text(
        text = stringResource(R.string.label_choose_action),
        style = MaterialTheme.typography.titleMedium,
    )
    Spacer(Modifier.height(12.dp))
    actions.forEach { action ->
        when (action) {
            NextAction.IdentifyEmail -> IdentifyCard(
                labelRes = R.string.action_identify_email,
                hintRes = R.string.hint_email,
                keyboardType = KeyboardType.Email,
                submitRes = R.string.action_submit,
                onSubmit = { viewModel.identifyEmail(it) },
            )

            NextAction.IdentifyPhone -> IdentifyCard(
                labelRes = R.string.action_identify_phone,
                hintRes = R.string.hint_phone,
                keyboardType = KeyboardType.Phone,
                submitRes = R.string.action_submit,
                onSubmit = { viewModel.identifyPhone(it) },
            )

            is NextAction.ChallengeEmail -> ChallengeEmailCard(
                identifier = action.identifier,
                onChallenge = { viewModel.challengeEmail(action.index ?: 0) },
            )

            is NextAction.VerifyOtp -> VerifyOtpCard(
                identifier = action.identifier,
                onVerify = { code, type -> viewModel.verifyOtp(code, type) },
            )

            is NextAction.Unknown -> InfoCard(
                stringResource(R.string.label_unsupported_action, action.rawAction),
            )
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun IdentifyCard(
    labelRes: Int,
    hintRes: Int,
    keyboardType: KeyboardType,
    submitRes: Int,
    onSubmit: (String) -> Unit,
) {
    var value by rememberSaveable(labelRes) { mutableStateOf("") }
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(labelRes), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                label = { Text(stringResource(hintRes)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = keyboardType,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(
                    onDone = { if (value.isNotBlank()) onSubmit(value.trim()) },
                ),
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { onSubmit(value.trim()) },
                enabled = value.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(submitRes))
            }
        }
    }
}

@Composable
private fun ChallengeEmailCard(identifier: String?, onChallenge: () -> Unit) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                stringResource(R.string.action_challenge_email),
                style = MaterialTheme.typography.titleSmall,
            )
            if (identifier != null) {
                Spacer(Modifier.height(4.dp))
                Text(identifier, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(12.dp))
            Button(onClick = onChallenge, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_challenge_email))
            }
        }
    }
}

@Composable
private fun VerifyOtpCard(identifier: String?, onVerify: (String, OtpType) -> Unit) {
    var code by rememberSaveable { mutableStateOf("") }
    var type by remember { mutableStateOf(OtpType.OOB) }
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                stringResource(R.string.action_verify_otp),
                style = MaterialTheme.typography.titleSmall,
            )
            if (identifier != null) {
                Spacer(Modifier.height(4.dp))
                Text(identifier, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = type == OtpType.OOB,
                    onClick = { type = OtpType.OOB },
                    label = { Text("OOB") },
                )
                FilterChip(
                    selected = type == OtpType.TOTP,
                    onClick = { type = OtpType.TOTP },
                    label = { Text("TOTP") },
                )
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = code,
                onValueChange = { code = it },
                label = { Text(stringResource(R.string.hint_otp)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(
                    onDone = { if (code.isNotBlank()) onVerify(code.trim(), type) },
                ),
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { onVerify(code.trim(), type) },
                enabled = code.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.action_verify))
            }
        }
    }
}

@Composable
private fun InfoCard(text: String) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.Top) {
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

// The multi-step flow ends here; show only non-sensitive fields — never the token values.
private fun formatCredentials(credentials: Credentials): String = buildString {
    appendLine("Authenticated ✓")
    appendLine()
    appendLine("token type:   ${credentials.type}")
    appendLine("scope:        ${credentials.scope ?: "(none)"}")
    appendLine("expires at:   ${credentials.expiresAt}")
    appendLine("refresh token: ${if (credentials.refreshToken != null) "present" else "absent"}")
}

private fun formatError(error: EmbeddedAuthException): String = buildString {
    appendLine("Authorize step failed.")
    appendLine()
    appendLine("code:          ${error.code}")
    appendLine("description:   ${error.description}")
    appendLine("HTTP status:   ${error.statusCode}")
    appendLine("network error: ${error.isNetworkError}")
    // Surface the underlying cause chain — client-side parse errors hide here, not in code/description.
    var cause = error.cause
    if (cause != null) {
        appendLine()
        appendLine("cause:")
        while (cause != null) {
            appendLine("  • ${cause::class.java.simpleName}: ${cause.message}")
            cause = cause.cause
        }
    }
}
