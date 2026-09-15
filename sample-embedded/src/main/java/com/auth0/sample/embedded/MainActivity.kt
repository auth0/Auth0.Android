package com.auth0.sample.embedded

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.auth0.sample.embedded.ui.theme.EmbeddedDiscoveryTheme

public class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            EmbeddedDiscoveryTheme {
                EmbeddedScreen()
            }
        }
    }
}
