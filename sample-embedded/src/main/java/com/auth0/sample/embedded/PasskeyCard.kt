package com.auth0.sample.embedded

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
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
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.NoCredentialException
import kotlinx.coroutines.launch

/**
 * Offers passkey sign-in. Runs the Credential Manager ceremony with the server's [requestJson] and
 * hands the resulting `authenticationResponseJson` to [onAssertion]. A canceled or failed ceremony
 * leaves the flow unchanged, so the user can retry or pick another action.
 */
@Composable
internal fun PasskeyCard(
    rpId: String,
    requestJson: String,
    onAssertion: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var errorRes by remember(requestJson) { mutableStateOf<Int?>(null) }
    var inProgress by remember(requestJson) { mutableStateOf(false) }

    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.label_passkey), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(rpId, style = MaterialTheme.typography.bodySmall)
            errorRes?.let {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(it),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = {
                    errorRes = null
                    inProgress = true
                    scope.launch {
                        errorRes = try {
                            onAssertion(requestPasskeyAssertion(context, requestJson))
                            null
                        } catch (e: GetCredentialCancellationException) {
                            null
                        } catch (e: NoCredentialException) {
                            R.string.error_no_passkey
                        } catch (e: GetCredentialException) {
                            R.string.error_passkey_failed
                        }
                        inProgress = false
                    }
                },
                enabled = !inProgress,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.action_use_passkey))
            }
        }
    }
}

/**
 * Shows the platform passkey sheet for [requestJson] and returns the chosen passkey's
 * `authenticationResponseJson`, ready for [com.auth0.android.embedded.EmbeddedAuthClient.verifyPasskey].
 */
private suspend fun requestPasskeyAssertion(context: Context, requestJson: String): String {
    val response = CredentialManager.create(context).getCredential(
        context,
        GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson))),
    )
    val credential = response.credential as? PublicKeyCredential
        ?: throw GetCredentialUnknownException("The platform returned a credential that isn't a passkey.")
    return credential.authenticationResponseJson
}
