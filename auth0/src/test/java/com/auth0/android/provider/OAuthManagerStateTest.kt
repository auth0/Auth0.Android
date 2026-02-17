package com.auth0.android.provider

import android.graphics.Color
import com.auth0.android.Auth0
import org.mockito.kotlin.mock
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
internal class OAuthManagerStateTest {

    @Test
    fun `serialize should work`() {
        val auth0 = Auth0.getInstance("clientId", "domain")
        val state = OAuthManagerState(
            auth0 = auth0,
            parameters = mapOf("param1" to "value1"),
            headers = mapOf("header1" to "value1"),
            requestCode = 1,
            ctOptions = CustomTabsOptions.newBuilder()
                .showTitle(true)
                .withToolbarColor(Color.RED)
                .withBrowserPicker(
                    BrowserPicker.newBuilder().withAllowedPackages(emptyList()).build()
                )
                .build(),
            pkce = PKCE(mock(), "redirectUri", mapOf("header1" to "value1")),
            idTokenVerificationLeeway = 1,
            idTokenVerificationIssuer = "issuer"
        )

        val json = state.serializeToJson()

        Assert.assertTrue(json.isNotBlank())

        val deserializedState = OAuthManagerState.deserializeState(json)

        Assert.assertEquals(mapOf("param1" to "value1"), deserializedState.parameters)
        Assert.assertEquals(mapOf("header1" to "value1"), deserializedState.headers)
        Assert.assertEquals(1, deserializedState.requestCode)
        Assert.assertEquals("redirectUri", deserializedState.pkce?.redirectUri)
        Assert.assertEquals(1, deserializedState.idTokenVerificationLeeway)
        Assert.assertEquals("issuer", deserializedState.idTokenVerificationIssuer)
    }

    @Test
    fun `serialize should persist dPoPEnabled flag as true`() {
        val auth0 = Auth0.getInstance("clientId", "domain")
        val state = OAuthManagerState(
            auth0 = auth0,
            parameters = mapOf("param1" to "value1"),
            headers = mapOf("header1" to "value1"),
            requestCode = 1,
            ctOptions = CustomTabsOptions.newBuilder()
                .showTitle(true)
                .withBrowserPicker(
                    BrowserPicker.newBuilder().withAllowedPackages(emptyList()).build()
                )
                .build(),
            pkce = PKCE(mock(), "redirectUri", mapOf("header1" to "value1")),
            idTokenVerificationLeeway = 1,
            idTokenVerificationIssuer = "issuer",
            dPoPEnabled = true
        )

        val json = state.serializeToJson()

        Assert.assertTrue(json.isNotBlank())
        Assert.assertTrue(json.contains("\"dPoPEnabled\":true"))

        val deserializedState = OAuthManagerState.deserializeState(json)

        Assert.assertTrue(deserializedState.dPoPEnabled)
    }

    @Test
    fun `serialize should persist dPoPEnabled flag as false by default`() {
        val auth0 = Auth0.getInstance("clientId", "domain")
        val state = OAuthManagerState(
            auth0 = auth0,
            parameters = mapOf("param1" to "value1"),
            headers = mapOf("header1" to "value1"),
            requestCode = 1,
            ctOptions = CustomTabsOptions.newBuilder()
                .showTitle(true)
                .withBrowserPicker(
                    BrowserPicker.newBuilder().withAllowedPackages(emptyList()).build()
                )
                .build(),
            pkce = PKCE(mock(), "redirectUri", mapOf("header1" to "value1")),
            idTokenVerificationLeeway = 1,
            idTokenVerificationIssuer = "issuer"
        )

        val json = state.serializeToJson()

        val deserializedState = OAuthManagerState.deserializeState(json)

        Assert.assertFalse(deserializedState.dPoPEnabled)
    }

    @Test
    fun `deserialize should default dPoPEnabled to false when field is missing from JSON`() {
        val auth0 = Auth0.getInstance("clientId", "domain")
        val state = OAuthManagerState(
            auth0 = auth0,
            parameters = emptyMap(),
            headers = emptyMap(),
            requestCode = 0,
            ctOptions = CustomTabsOptions.newBuilder()
                .showTitle(true)
                .withBrowserPicker(
                    BrowserPicker.newBuilder().withAllowedPackages(emptyList()).build()
                )
                .build(),
            pkce = PKCE(mock(), "redirectUri", emptyMap()),
            idTokenVerificationLeeway = null,
            idTokenVerificationIssuer = null
        )

        val json = state.serializeToJson()
        // Remove the dPoPEnabled field to simulate legacy JSON
        val legacyJson = json.replace(",\"dPoPEnabled\":false", "")

        val deserializedState = OAuthManagerState.deserializeState(legacyJson)

        Assert.assertFalse(deserializedState.dPoPEnabled)
    }
}
