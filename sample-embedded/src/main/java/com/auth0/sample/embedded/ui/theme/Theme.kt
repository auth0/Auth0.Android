package com.auth0.sample.embedded.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

// Simple black-on-white scheme; no dark variant, no accent shades.
private val BlackWhiteColors = lightColorScheme(
    primary = Black,
    onPrimary = White,
    background = White,
    onBackground = Black,
    surface = White,
    onSurface = Black,
)

@Composable
public fun EmbeddedDiscoveryTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = BlackWhiteColors,
        content = content,
    )
}
