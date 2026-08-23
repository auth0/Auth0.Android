package com.auth0.android.embedded

import com.auth0.android.request.HttpMethod
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import com.google.gson.Gson
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.hasKey
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayInputStream

@RunWith(RobolectricTestRunner::class)
public class FakeDiscoveryClientTest {

    private class RecordingClient : NetworkingClient {
        var loadedUrl: String? = null

        override fun load(url: String, options: RequestOptions): ServerResponse {
            loadedUrl = url
            return ServerResponse(204, ByteArrayInputStream(ByteArray(0)), emptyMap())
        }
    }

    private val delegate = RecordingClient()
    private val client = FakeDiscoveryClient(delegate)
    private val options = RequestOptions(HttpMethod.GET)

    @Test
    public fun `answers discovery without reaching the delegate`() {
        client.load("https://my-tenant.auth0.com/e/discovery?client_id=abc", options)

        assertThat(delegate.loadedUrl, `is`(nullValue()))
    }

    @Test
    public fun `answers discovery with the canned payload as a successful json response`() {
        val response = client.load("https://my-tenant.auth0.com/e/discovery?client_id=abc", options)

        assertThat(response.isSuccess(), `is`(true))
        assertThat(response.isJson(), `is`(true))
        assertThat(
            response.body.reader().readText(),
            equalTo(FakeDiscoveryData.SUCCESS_RESPONSE)
        )
    }

    @Test
    public fun `answers discovery when no query parameters were added`() {
        val response = client.load("https://my-tenant.auth0.com/e/discovery", options)

        assertThat(response.isSuccess(), `is`(true))
        assertThat(delegate.loadedUrl, `is`(nullValue()))
    }

    @Test
    public fun `passes every other request to the delegate untouched`() {
        val response = client.load("https://my-tenant.auth0.com/oauth/token", options)

        assertThat(delegate.loadedUrl, equalTo("https://my-tenant.auth0.com/oauth/token"))
        assertThat(response.statusCode, equalTo(204))
    }

    @Test
    public fun `does not intercept a path that merely contains the discovery segment`() {
        client.load("https://my-tenant.auth0.com/e/discovery/details", options)

        assertThat(delegate.loadedUrl, `is`(notNullValue()))
    }

    @Test
    public fun `serves a payload the discovery adapter can parse`() {
        val response = client.load("https://my-tenant.auth0.com/e/discovery", options)
        val result = Gson()
            .fromJson(response.body.reader(), DiscoveryResponse::class.java)
            .toDiscoveryResult()

        assertThat(result.options.size, equalTo(7))
        assertThat(
            result.types, equalTo(
                setOf(
                    GrantType.AUTHORIZATION_CODE,
                    GrantType.NATIVE_SOCIAL,
                    GrantType.PASSWORD,
                    GrantType.PASSKEY,
                    GrantType.PASSWORDLESS_OTP,
                    GrantType.PASSWORD_REALM
                )
            )
        )
    }

    @Test
    public fun `declares the content type so the error adapter would treat the body as json`() {
        val response = client.load("https://my-tenant.auth0.com/e/discovery", options)

        assertThat(response.headers, hasKey("Content-Type"))
    }
}
