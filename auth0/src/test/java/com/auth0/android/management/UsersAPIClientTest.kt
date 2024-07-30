package com.auth0.android.management

import android.content.Context
import android.content.res.Resources
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationAPIClientTest
import com.auth0.android.request.HttpMethod.GET
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ThreadSwitcherShadow
import com.auth0.android.result.UserIdentity
import com.auth0.android.result.UserProfile
import com.auth0.android.util.*
import com.auth0.android.util.SSLTestUtils.testClient
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.nhaarman.mockitokotlin2.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.hamcrest.Matchers.instanceOf
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.collection.IsMapContaining
import org.hamcrest.collection.IsMapWithSize
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLooper
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.*


@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ThreadSwitcherShadow::class])
public class UsersAPIClientTest {
    private lateinit var client: UsersAPIClient
    private lateinit var gson: Gson
    private lateinit var mockAPI: UsersAPIMockServer

    @Before
    public fun setUp() {
        mockAPI = UsersAPIMockServer()
        val domain = mockAPI.domain
        val auth0 = Auth0.getInstance(CLIENT_ID, domain, domain)
        auth0.networkingClient = testClient
        client = UsersAPIClient(auth0, TOKEN_PRIMARY)
        gson = GsonBuilder().serializeNulls().create()
    }

    @After
    public fun tearDown() {
        mockAPI.shutdown()
    }

    @Test
    public fun shouldUseCustomNetworkingClient() {
        val account = Auth0.getInstance("client-id", "https://tenant.auth0.com/")
        val jsonResponse = """{"id": "undercover"}"""
        val inputStream: InputStream = ByteArrayInputStream(jsonResponse.toByteArray())
        val response = ServerResponse(200, inputStream, emptyMap())
        val networkingClient: NetworkingClient = mock()

        whenever(networkingClient.load(any<String>(), any<RequestOptions>())).thenReturn(response)
        account.networkingClient = networkingClient
        val client = UsersAPIClient(account, "token.token")
        val request = client.getProfile("undercover")

        request.execute()
        ShadowLooper.idleMainLooper()
        argumentCaptor<RequestOptions>().apply {
            verify(networkingClient).load(eq("https://tenant.auth0.com/api/v2/users/undercover"), capture())
            assertThat(firstValue, Matchers.`is`(notNullValue()))
            assertThat(firstValue.method, Matchers.`is`(instanceOf(GET::class.java)))
            assertThat(firstValue.parameters, IsMapWithSize.anEmptyMap())
            assertThat(firstValue.headers, IsMapContaining.hasKey("Auth0-Client"))
        }
    }

    @Test
    public fun shouldSetAuth0UserAgentIfPresent() {
        val auth0UserAgent: Auth0UserAgent = mock()
        val factory: RequestFactory<ManagementException> = mock()
        val account = Auth0.getInstance(CLIENT_ID, DOMAIN)

        whenever(auth0UserAgent.value).thenReturn("the-user-agent-data")
        account.auth0UserAgent = auth0UserAgent
        UsersAPIClient(account, factory, gson)

        verify(factory).setAuth0ClientInfo("the-user-agent-data")
    }

    @Test
    public fun shouldCreateClientWithAccountInfo() {
        val client = UsersAPIClient(Auth0.getInstance(CLIENT_ID, DOMAIN), TOKEN_PRIMARY)
        assertThat(client, Matchers.`is`(notNullValue()))
        assertThat(client.clientId, Matchers.equalTo(CLIENT_ID))
        assertThat(client.baseURL, Matchers.equalTo("https://$DOMAIN/"))
    }

    @Test
    public fun shouldCreateClientWithContextInfo() {
        val context: Context = mock()
        val resources: Resources = mock()

        whenever(context.packageName).thenReturn("com.myapp")
        whenever(context.resources).thenReturn(resources)
        whenever(resources.getIdentifier(
            eq("com_auth0_client_id"),
            eq("string"),
            eq("com.myapp")
        )).thenReturn(222)
        whenever(resources.getIdentifier(
            eq("com_auth0_domain"),
            eq("string"),
            eq("com.myapp")
        )).thenReturn(333)
        whenever(context.getString(eq(222))).thenReturn(CLIENT_ID)
        whenever(context.getString(eq(333))).thenReturn(DOMAIN)

        val client = UsersAPIClient(Auth0.getInstance(context), TOKEN_PRIMARY)
        assertThat(client, Matchers.`is`(notNullValue()))
        assertThat(client.clientId, Matchers.`is`(CLIENT_ID))
        assertThat(client.baseURL, Matchers.equalTo("https://$DOMAIN/"))
    }

    @Test
    public fun shouldLinkAccount() {
        mockAPI.willReturnSuccessfulLink()
        val callback = MockManagementCallback<List<UserIdentity>>()
        client.link(USER_ID_PRIMARY, TOKEN_SECONDARY)
            .start(callback)
        ShadowLooper.idleMainLooper()

        val request = mockAPI.takeRequest()
        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY/identities")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_POST))

        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry(KEY_LINK_WITH, TOKEN_SECONDARY))

        val typeToken: TypeToken<List<UserIdentity>> = object : TypeToken<List<UserIdentity>>() {}
        assertThat(callback, ManagementCallbackMatcher.hasPayloadOfType(typeToken))
        assertThat(callback.payload.size, Matchers.`is`(2))
    }

    @Test
    public fun shouldLinkAccountSync() {
        mockAPI.willReturnSuccessfulLink()
        val result = client.link(USER_ID_PRIMARY, TOKEN_SECONDARY)
            .execute()
        val request = mockAPI.takeRequest()

        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY/identities")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_POST))

        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry(KEY_LINK_WITH, TOKEN_SECONDARY))

        val typeToken: TypeToken<List<UserIdentity>> = object : TypeToken<List<UserIdentity>>() {}
        assertThat(result, TypeTokenMatcher.isA(typeToken))
        assertThat(result.size, Matchers.`is`(2))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitLinkAccount(): Unit = runTest {
        mockAPI.willReturnSuccessfulLink()
        val result = client.link(USER_ID_PRIMARY, TOKEN_SECONDARY)
            .await()
        val request = mockAPI.takeRequest()

        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY/identities")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_POST))

        val body = bodyFromRequest<String>(request)
        assertThat(body, Matchers.hasEntry(KEY_LINK_WITH, TOKEN_SECONDARY))

        val typeToken: TypeToken<List<UserIdentity>> = object : TypeToken<List<UserIdentity>>() {}
        assertThat(result, TypeTokenMatcher.isA(typeToken))
        assertThat(result.size, Matchers.`is`(2))
    }


    @Test
    public fun shouldUnlinkAccount() {
        mockAPI.willReturnSuccessfulUnlink()
        val callback = MockManagementCallback<List<UserIdentity>>()
        client.unlink(USER_ID_PRIMARY, USER_ID_SECONDARY, PROVIDER)
            .start(callback)
        ShadowLooper.idleMainLooper()

        val request = mockAPI.takeRequest()
        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY/identities/$PROVIDER/$USER_ID_SECONDARY")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_DELETE))

        val body = bodyFromRequest<String>(request)
        assertThat(body, IsMapWithSize.anEmptyMap())

        val typeToken: TypeToken<List<UserIdentity>> = object : TypeToken<List<UserIdentity>>() {}
        assertThat(callback, ManagementCallbackMatcher.hasPayloadOfType(typeToken))
        assertThat(callback.payload.size, Matchers.`is`(1))
    }

    @Test
    public fun shouldUnlinkAccountSync() {
        mockAPI.willReturnSuccessfulUnlink()
        val result = client.unlink(USER_ID_PRIMARY, USER_ID_SECONDARY, PROVIDER)
            .execute()

        val request = mockAPI.takeRequest()
        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY/identities/$PROVIDER/$USER_ID_SECONDARY")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_DELETE))

        val body = bodyFromRequest<String>(request)
        assertThat(body, IsMapWithSize.anEmptyMap())

        val typeToken: TypeToken<List<UserIdentity>> = object : TypeToken<List<UserIdentity>>() {}
        assertThat(result, TypeTokenMatcher.isA(typeToken))
        assertThat(result.size, Matchers.`is`(1))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitUnlinkAccount(): Unit = runTest {
        mockAPI.willReturnSuccessfulUnlink()
        val result = client.unlink(USER_ID_PRIMARY, USER_ID_SECONDARY, PROVIDER)
            .await()

        val request = mockAPI.takeRequest()
        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY/identities/$PROVIDER/$USER_ID_SECONDARY")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_DELETE))

        val body = bodyFromRequest<String>(request)
        assertThat(body, IsMapWithSize.anEmptyMap())

        val typeToken: TypeToken<List<UserIdentity>> = object : TypeToken<List<UserIdentity>>() {}
        assertThat(result, TypeTokenMatcher.isA(typeToken))
        assertThat(result.size, Matchers.`is`(1))
    }

    @Test
    public fun shouldUpdateUserMetadata() {
        mockAPI.willReturnUserProfile()
        val metadata: MutableMap<String, Any?> = HashMap()
        metadata["boolValue"] = true
        metadata["name"] = "my_name"
        metadata["list"] = listOf("my", "name", "is")
        val callback = MockManagementCallback<UserProfile>()
        client.updateMetadata(USER_ID_PRIMARY, metadata)
            .start(callback)
        ShadowLooper.idleMainLooper()

        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY"))
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_PATCH))

        val body = bodyFromRequest<Any?>(request)
        assertThat(body, Matchers.hasKey(KEY_USER_METADATA))
        assertThat(body[KEY_USER_METADATA], Matchers.`is`(Matchers.equalTo(metadata)))
        assertThat(
            callback,
            ManagementCallbackMatcher.hasPayloadOfType(UserProfile::class.java)
        )
    }

    @Test
    public fun shouldUpdateUserMetadataSync() {
        mockAPI.willReturnUserProfile()
        val metadata: MutableMap<String, Any?> = HashMap()
        metadata["boolValue"] = true
        metadata["name"] = "my_name"
        metadata["list"] = listOf("my", "name", "is")

        val result = client.updateMetadata(USER_ID_PRIMARY, metadata)
            .execute()
        val request = mockAPI.takeRequest()

        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_PATCH))

        val body = bodyFromRequest<Any?>(request)
        assertThat(body, Matchers.hasKey(KEY_USER_METADATA))
        assertThat(body[KEY_USER_METADATA], Matchers.`is`(Matchers.equalTo(metadata)))
        assertThat(result, Matchers.isA(UserProfile::class.java))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitUpdateUserMetadata(): Unit = runTest {
        mockAPI.willReturnUserProfile()
        val metadata: MutableMap<String, Any?> = HashMap()
        metadata["boolValue"] = true
        metadata["name"] = "my_name"
        metadata["list"] = listOf("my", "name", "is")

        val result = client.updateMetadata(USER_ID_PRIMARY, metadata)
            .await()
        val request = mockAPI.takeRequest()

        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(request.method, Matchers.equalTo(METHOD_PATCH))

        val body = bodyFromRequest<Any?>(request)
        assertThat(body, Matchers.hasKey(KEY_USER_METADATA))
        assertThat(body[KEY_USER_METADATA], Matchers.`is`(Matchers.equalTo(metadata)))
        assertThat(result, Matchers.isA(UserProfile::class.java))
    }

    @Test
    public fun shouldGetUserProfileSync() {
        mockAPI.willReturnUserProfile()
        val result = client.getProfile(USER_ID_PRIMARY)
            .execute()
        val request = mockAPI.takeRequest()

        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(
            request.method,
            Matchers.equalTo(METHOD_GET)
        )
        assertThat(result, Matchers.isA(UserProfile::class.java))
    }

    @Test
    @ExperimentalCoroutinesApi
    public fun shouldAwaitGetUserProfile(): Unit = runTest {
        mockAPI.willReturnUserProfile()
        val result = client.getProfile(USER_ID_PRIMARY)
            .await()
        val request = mockAPI.takeRequest()

        assertThat(
            request.path,
            Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY")
        )
        assertThat(
            request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY)
        )
        assertThat(
            request.method,
            Matchers.equalTo(METHOD_GET)
        )
        assertThat(result, Matchers.isA(UserProfile::class.java))
    }

    @Test
    public fun shouldGetUserProfile() {
        mockAPI.willReturnUserProfile()
        val callback = MockManagementCallback<UserProfile>()
        client.getProfile(USER_ID_PRIMARY)
            .start(callback)
        ShadowLooper.idleMainLooper()

        val request = mockAPI.takeRequest()
        assertThat(request.path, Matchers.equalTo("/api/v2/users/$USER_ID_PRIMARY"))
        assertThat(request.getHeader(HEADER_AUTHORIZATION),
            Matchers.equalTo(BEARER + TOKEN_PRIMARY))
        assertThat(request.method, Matchers.equalTo(METHOD_GET))
        assertThat(
            callback, ManagementCallbackMatcher.hasPayloadOfType(
                UserProfile::class.java
            )
        )
    }

    private fun <T> bodyFromRequest(request: RecordedRequest): Map<String, T> {
        val mapType = object : TypeToken<Map<String?, T>?>() {}.type
        return gson.fromJson(request.body.readUtf8(), mapType)
    }

    private companion object {
        private const val CLIENT_ID = "CLIENTID"
        private const val DOMAIN = "samples.auth0.com"
        private const val USER_ID_PRIMARY = "primaryUserId"
        private const val USER_ID_SECONDARY = "secondaryUserId"
        private const val TOKEN_PRIMARY = "primaryToken"
        private const val TOKEN_SECONDARY = "secondaryToken"
        private const val PROVIDER = "provider"
        private const val HEADER_AUTHORIZATION = "Authorization"
        private const val BEARER = "Bearer "
        private const val METHOD_POST = "POST"
        private const val METHOD_DELETE = "DELETE"
        private const val METHOD_PATCH = "PATCH"
        private const val METHOD_GET = "GET"
        private const val KEY_LINK_WITH = "link_with"
        private const val KEY_USER_METADATA = "user_metadata"
    }
}