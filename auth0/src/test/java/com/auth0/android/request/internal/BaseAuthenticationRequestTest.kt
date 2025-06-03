package com.auth0.android.request.internal

import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.request.*
import com.auth0.android.result.Credentials
import com.nhaarman.mockitokotlin2.*
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.collection.IsMapContaining
import org.hamcrest.collection.IsMapWithSize
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.mockito.internal.verification.VerificationModeFactory
import org.robolectric.RobolectricTestRunner
import java.io.InputStream
import java.util.*

@RunWith(RobolectricTestRunner::class)
public class BaseAuthenticationRequestTest {

    @Mock
    private lateinit var client: NetworkingClient

    @Mock
    private lateinit var resultAdapter: JsonAdapter<Credentials>

    @Mock
    private lateinit var errorAdapter: ErrorAdapter<AuthenticationException>

    private val optionsCaptor: KArgumentCaptor<RequestOptions> = argumentCaptor()

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
    }

    private fun createRequest(url: String): AuthenticationRequest {
        val baseRequest: Request<Credentials, AuthenticationException> =
            BaseRequest(HttpMethod.POST, url, client, resultAdapter, errorAdapter)
        val request: AuthenticationRequest = BaseAuthenticationRequest(baseRequest, "client-id", url)
        return Mockito.spy(request)
    }

    @Test
    @Throws(Exception::class)
    public fun shouldSetGrantType() {
        mockSuccessfulServerResponse()
        createRequest(BASE_URL)
            .setGrantType("grantType")
            .execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, Any> = optionsCaptor.firstValue.parameters
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("grant_type", "grantType"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldSetConnection() {
        mockSuccessfulServerResponse()
        createRequest(BASE_URL)
            .setConnection("my-connection")
            .execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, Any> = optionsCaptor.firstValue.parameters
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("connection", "my-connection"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldSetRealm() {
        mockSuccessfulServerResponse()
        createRequest(BASE_URL)
            .setRealm("my-realm")
            .execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, Any> = optionsCaptor.firstValue.parameters
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("realm", "my-realm"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldEnforceOidcScope() {
        mockSuccessfulServerResponse()
        createRequest(BASE_URL)
            .setScope("email profile")
            .execute()

        createRequest(BASE_URL)
            .addParameter("scope", "profile")
            .execute()

        createRequest(BASE_URL)
            .addParameters(mapOf("scope" to "name"))
            .execute()

        createRequest(BASE_URL)
            .addParameters(mapOf("scope" to ""))
            .execute()

        verify(client, VerificationModeFactory.times(4)).load(eq(BASE_URL), optionsCaptor.capture())

        val values1: Map<String, Any> = optionsCaptor.allValues[0].parameters
        MatcherAssert.assertThat(values1, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values1, IsMapContaining.hasEntry("scope", "email profile openid"))

        val values2: Map<String, Any> = optionsCaptor.allValues[1].parameters
        MatcherAssert.assertThat(values2, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values2, IsMapContaining.hasEntry("scope", "profile openid"))

        val values3: Map<String, Any> = optionsCaptor.allValues[2].parameters
        MatcherAssert.assertThat(values3, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values3, IsMapContaining.hasEntry("scope", "name openid"))

        val values4: Map<String, Any> = optionsCaptor.allValues[3].parameters
        MatcherAssert.assertThat(values4, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values4, IsMapContaining.hasEntry("scope", "openid"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldSetAudience() {
        mockSuccessfulServerResponse()
        createRequest(BASE_URL)
            .setAudience("my-api")
            .execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, Any> = optionsCaptor.firstValue.parameters
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(1))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("audience", "my-api"))
    }

    @Test
    @Throws(Exception::class)
    public fun shouldAddAuthenticationParameters() {
        mockSuccessfulServerResponse()
        val parameters = HashMap<String, String>()
        parameters["extra"] = "value"
        parameters["123"] = "890"
        createRequest(BASE_URL)
            .addParameters(parameters)
            .execute()
        verify(client).load(eq(BASE_URL), optionsCaptor.capture())
        val values: Map<String, Any> = optionsCaptor.firstValue.parameters
        MatcherAssert.assertThat(values, IsMapWithSize.aMapWithSize(2))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("extra", "value"))
        MatcherAssert.assertThat(values, IsMapContaining.hasEntry("123", "890"))
    }

    @Test
    public fun shouldSetIdTokenVerificationIssuer() {
        val request = createRequest(BASE_URL) as BaseAuthenticationRequest
        MatcherAssert.assertThat(request.idTokenVerificationIssuer, CoreMatchers.`is`(CoreMatchers.equalTo(BASE_URL)))
        request.withIdTokenVerificationIssuer("custom")
        MatcherAssert.assertThat(request.idTokenVerificationIssuer, CoreMatchers.`is`(CoreMatchers.equalTo("custom")))
    }

    @Test
    public fun shouldSetIdTokenVerificationLeeway() {
        val request = createRequest(BASE_URL) as BaseAuthenticationRequest
        MatcherAssert.assertThat(request.idTokenVerificationLeeway, CoreMatchers.nullValue())
        request.withIdTokenVerificationLeeway(0)
        MatcherAssert.assertThat(request.idTokenVerificationLeeway, CoreMatchers.`is`(CoreMatchers.equalTo(0)))
    }

    @Test
    public fun shouldValidateClaimsWhenSet() {
        val request = createRequest(BASE_URL) as BaseAuthenticationRequest
        MatcherAssert.assertThat(request.validateClaims, CoreMatchers.`is`(CoreMatchers.equalTo(false)))
        request.validateClaims()
        MatcherAssert.assertThat(request.validateClaims, CoreMatchers.`is`(CoreMatchers.equalTo(true)))
    }

    @Throws(Exception::class)
    private fun mockSuccessfulServerResponse() {
        val inputStream: InputStream = mock()
        val credentials: Credentials = mock()
        whenever(inputStream.read()).thenReturn(123)
        whenever(resultAdapter.fromJson(any(), any())).thenReturn(credentials)
        val response = ServerResponse(200, inputStream, emptyMap())
        whenever(client.load(eq(BASE_URL), any())).thenReturn(response)
    }

    private companion object {
        private const val BASE_URL = "https://auth0.com/oauth/token"
    }
}