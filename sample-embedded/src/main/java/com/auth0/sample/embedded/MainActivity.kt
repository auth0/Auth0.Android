package com.auth0.sample.embedded

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewmodel.compose.viewModel
import com.auth0.sample.embedded.ui.theme.EmbeddedDiscoveryTheme

public class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            EmbeddedDiscoveryTheme {
                EmbeddedApp()
            }
        }
    }
}

@Composable
private fun EmbeddedApp(viewModel: EmbeddedViewModel = viewModel()) {
    var showAuthorize by rememberSaveable { mutableStateOf(false) }
    var authorizeConnection by rememberSaveable { mutableStateOf("Username-Password-Authentication") }

    if (showAuthorize) {
        AuthorizeScreen(
            viewModel = viewModel,
            initialConnection = authorizeConnection,
            onBack = {
                viewModel.resetAuthorize()
                showAuthorize = false
            },
        )
    } else {
        EmbeddedScreen(
            viewModel = viewModel,
            onAuthorize = { connection ->
                authorizeConnection = connection
                showAuthorize = true
            },
        )
    }
}
