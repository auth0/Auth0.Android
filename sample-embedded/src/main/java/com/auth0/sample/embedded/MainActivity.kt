package com.auth0.sample.embedded

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
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
    AuthorizeScreen(
        viewModel = viewModel,
        initialConnection = "Username-Password-Authentication",
    )
}
