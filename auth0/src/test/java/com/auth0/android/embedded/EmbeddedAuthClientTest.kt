package com.auth0.android.embedded

import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.util.EmbeddedAuthMockServer
import com.auth0.android.util.SSLTestUtils.testClient
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.containsInAnyOrder
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
public class EmbeddedAuthClientTest {

    private lateinit var mockAPI: EmbeddedAuthMockServer
    private lateinit var client: EmbeddedAuthClient

    private val auth0: Auth0
        get() {
            val auth0 = Auth0.getInstance(CLIENT_ID, mockAPI.domain, mockAPI.domain)
            auth0.networkingClient = testClient
            return auth0
        }

    @Before
    public fun setUp() {
        mockAPI = EmbeddedAuthMockServer()
        client = EmbeddedAuthClient(auth0)
    }

    @After
    public fun tearDown() {
        mockAPI.shutdown()
    }

    @Test
    public fun `discover should GET the discovery endpoint with the client id`() {
        mockAPI.willReturnEmptyDiscovery()

        client.discover().execute()

        val request = mockAPI.takeRequest()
        assertThat(request.method, `is`("GET"))
        assertThat(request.requestUrl?.encodedPath, `is`("/e/discovery"))
        assertThat(request.requestUrl?.queryParameter("client_id"), `is`(CLIENT_ID))
        assertThat(request.requestUrl?.queryParameter("connection"), `is`(nullValue()))
    }

    @Test
    public fun `discover should add the connection query parameter when given`() {
        mockAPI.willReturnEmptyDiscovery()

        client.discover("my-connection").execute()

        val request = mockAPI.takeRequest()
        assertThat(request.requestUrl?.queryParameter("connection"), `is`("my-connection"))
    }

    @Test
    public fun `discover should send the Auth0-Client header`() {
        mockAPI.willReturnEmptyDiscovery()

        client.discover().execute()

        val request = mockAPI.takeRequest()
        assertThat(request.getHeader("Auth0-Client"), `is`(notNullValue()))
    }

    @Test
    public fun `discover should parse a full response into a DiscoveryResult`() {
        mockAPI.willReturnFullDiscovery()

        val result = client.discover().execute()

        assertThat(
            result.types,
            containsInAnyOrder(
                GrantType.PASSWORD,
                GrantType.PASSWORD_REALM,
                GrantType.PASSKEY,
                GrantType.PASSWORDLESS_OTP,
                GrantType.NATIVE_SOCIAL,
                GrantType.AUTHORIZATION_CODE,
                GrantType.UNKNOWN
            )
        )
    }

    @Test
    public fun `discover should surface an empty body 404 as an embedded auth error`() {
        mockAPI.willReturnNotEnabled()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.code, `is`(Auth0Exception.EMPTY_BODY_ERROR))
        assertThat(error?.statusCode, `is`(404))
        assertThat(error?.isNetworkError, `is`(false))
    }

    @Test
    public fun `discover should surface a non JSON error body`() {
        mockAPI.willReturnPlainTextError()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.code, `is`(Auth0Exception.NON_JSON_ERROR))
        assertThat(error?.description, `is`(EmbeddedAuthMockServer.PLAIN_TEXT_ERROR))
        assertThat(error?.statusCode, `is`(500))
    }

    @Test
    public fun `discover should surface a JSON error envelope`() {
        mockAPI.willReturnJsonError()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.code, `is`(EmbeddedAuthMockServer.ERROR_CODE))
        assertThat(error?.description, `is`(EmbeddedAuthMockServer.ERROR_DESCRIPTION))
        assertThat(error?.statusCode, `is`(400))
    }

    @Test
    public fun `discover should surface a network failure as a network error`() {
        mockAPI.shutdown()

        var error: EmbeddedAuthException? = null
        try {
            client.discover().execute()
        } catch (ex: EmbeddedAuthException) {
            error = ex
        }

        assertThat(error, `is`(notNullValue()))
        assertThat(error?.isNetworkError, `is`(true))
    }

    private companion object {
        private const val CLIENT_ID = "CLIENT_ID"
    }
}
