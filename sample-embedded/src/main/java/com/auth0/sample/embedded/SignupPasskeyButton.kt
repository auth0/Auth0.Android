package com.auth0.sample.embedded

import android.content.Context
import android.util.Log
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import kotlinx.coroutines.launch

private const val TAG = "SignupPasskey"

/**
 * Offers to finish signup with a passkey. Runs the Credential Manager ceremony with the server's [requestJson]
 * and hands the resulting `registrationResponseJson` to [onRegistration]. A canceled or failed ceremony leaves
 * the flow unchanged, so the user can retry or finish with a password, or with neither.
 */
@Composable
internal fun SignupPasskeyButton(
    requestJson: String,
    onRegistration: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var errorRes by remember(requestJson) { mutableStateOf<Int?>(null) }
    var inProgress by remember(requestJson) { mutableStateOf(false) }

    Column {
        errorRes?.let {
            Text(
                text = stringResource(it),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(8.dp))
        }
        OutlinedButton(
            onClick = {
                errorRes = null
                inProgress = true
                scope.launch {
                    errorRes = try {
                        onRegistration(requestPasskeyRegistration(context, requestJson))
                        null
                    } catch (e: CreateCredentialCancellationException) {
                        null
                    } catch (e: CreateCredentialException) {
                        Log.e(TAG, "Creating the passkey failed: ${e.type}: ${e.errorMessage}", e)
                        R.string.error_create_passkey_failed
                    }
                    inProgress = false
                }
            },
            enabled = !inProgress,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.action_create_passkey))
        }
    }
}

/**
 * Shows the platform passkey creation sheet for [requestJson] and returns the new passkey's
 * `registrationResponseJson`, ready for [com.auth0.android.embedded.EmbeddedAuthClient.confirmSignup].
 */
private suspend fun requestPasskeyRegistration(context: Context, requestJson: String): String {
    val response = CredentialManager.create(context).createCredential(
        context,
        CreatePublicKeyCredentialRequest(requestJson),
    )
    val registration = response as? CreatePublicKeyCredentialResponse
        ?: throw CreateCredentialUnknownException("The platform returned a credential that isn't a passkey.")
    return registration.registrationResponseJson
}
