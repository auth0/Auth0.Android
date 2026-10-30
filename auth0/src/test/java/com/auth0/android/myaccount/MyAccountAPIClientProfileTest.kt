package com.auth0.android.myaccount

import android.content.Context
import com.auth0.android.Auth0
import com.auth0.android.dpop.DPoPKeyStore
import com.auth0.android.dpop.DPoPUtil
import com.auth0.android.dpop.FakeECPrivateKey
import com.auth0.android.dpop.FakeECPublicKey
import com.auth0.android.myaccount.request.GetUserProfileOptions
import com.auth0.android.myaccount.request.UpdateUserProfileRequest
import com.auth0.android.result.MyAccountProfile
import com.auth0.android.result.ProfileFieldAccess
import com.auth0.android.result.ProfileFieldSource
import com.auth0.android.util.MockMyAccountCallback
import com.auth0.android.util.MyAccountAPIMockServer
import com.auth0.android.util.SSLTestUtils.testClient
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.RecordedRequest
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLooper

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
public class MyAccountAPIClientProfileTest {

    private lateinit var client: MyAccountAPIClient
    private lateinit var mockAPI: MyAccountAPIMockServer
    private lateinit var mockKeyStore: DPoPKeyStore
    private lateinit var mockContext: Context

    @Before
    public fun setUp() {
        mockAPI = MyAccountAPIMockServer()
        mockKeyStore = mock()
        mockContext = mock()
        whenever(mockContext.applicationContext).thenReturn(mockContext)
        DPoPUtil.keyStore = mockKeyStore
        client = MyAccountAPIClient(auth0, ACCESS_TOKEN)
    }

    @After
    public fun tearDown() {
        mockAPI.shutdown()
    }

    // getUserProfile

    @Test
    public fun `getUserProfile should send a GET request without query parameters by default`() {
        mockAPI.willReturnUserProfile()

        client.getUserProfile().execute()

        val request = mockAPI.takeRequest()
        assertThat(request.method, Matchers.`is`("GET"))
        assertThat(request.path, Matchers.`is`("/me/v1/profile"))
    }

    @Test
    public fun `getUserProfile should not send query parameters when fields is empty`() {
        mockAPI.willReturnUserProfile()

        client.getUserProfile(GetUserProfileOptions(fields = emptyList(), includeFields = true))
            .execute()

        assertThat(mockAPI.takeRequest().path, Matchers.`is`("/me/v1/profile"))
    }

    @Test
    public fun `getUserProfile should send comma-joined fields without include_fields by default`() {
        mockAPI.willReturnUserProfile()

        client.getUserProfile(GetUserProfileOptions(fields = listOf("given_name", "picture")))
            .execute()

        val url = mockAPI.takeRequest().requestUrl!!
        assertThat(url.queryParameter("fields"), Matchers.`is`("given_name,picture"))
        assertThat(url.queryParameterNames.contains("include_fields"), Matchers.`is`(false))
    }

    @Test
    public fun `getUserProfile should not send include_fields when it is true, the server default`() {
        mockAPI.willReturnUserProfile()

        client.getUserProfile(GetUserProfileOptions(listOf("given_name"), true)).execute()

        val url = mockAPI.takeRequest().requestUrl!!
        assertThat(url.queryParameter("fields"), Matchers.`is`("given_name"))
        assertThat(url.queryParameterNames.contains("include_fields"), Matchers.`is`(false))
    }

    @Test
    public fun `getUserProfile should not send include_fields false when fields is empty`() {
        mockAPI.willReturnUserProfile()

        client.getUserProfile(GetUserProfileOptions(includeFields = false)).execute()

        assertThat(mockAPI.takeRequest().path, Matchers.`is`("/me/v1/profile"))
    }

    @Test
    public fun `getUserProfile should send include_fields false`() {
        mockAPI.willReturnUserProfile()

        client.getUserProfile(GetUserProfileOptions(listOf("profile_policy"), false)).execute()

        val url = mockAPI.takeRequest().requestUrl!!
        assertThat(url.queryParameter("fields"), Matchers.`is`("profile_policy"))
        assertThat(url.queryParameter("include_fields"), Matchers.`is`("false"))
    }

    @Test
    public fun `getUserProfile should parse every profile field`() {
        mockAPI.willReturnUserProfile()

        val profile = client.getUserProfile().execute()

        assertThat(profile.userId, Matchers.`is`("auth0|123"))
        assertThat(profile.givenName, Matchers.`is`("Jane"))
        assertThat(profile.familyName, Matchers.`is`("Doe"))
        assertThat(profile.name, Matchers.`is`("Jane Doe"))
        assertThat(profile.nickname, Matchers.`is`("jane"))
        assertThat(profile.picture, Matchers.`is`("https://example.com/jane.png"))
        assertThat(profile.email, Matchers.`is`("jane@example.com"))
        assertThat(profile.emailVerified, Matchers.`is`(true))
        assertThat(profile.phoneNumber, Matchers.`is`("+15555550100"))
        assertThat(profile.phoneVerified, Matchers.`is`(false))
        assertThat(profile.username, Matchers.`is`("janedoe"))
        assertThat(profile.createdAt, Matchers.`is`("2026-01-01T00:00:00.000Z"))
        assertThat(profile.updatedAt, Matchers.`is`("2026-02-01T00:00:00.000Z"))
    }

    @Test
    public fun `getUserProfile should parse profile_policy`() {
        mockAPI.willReturnUserProfile()

        val policy = client.getUserProfile().execute().profilePolicy!!

        val givenName = policy["/given_name"]!!
        assertThat(givenName.access, Matchers.`is`(ProfileFieldAccess.READ_ONLY))
        assertThat(givenName.source, Matchers.`is`(ProfileFieldSource.IDP))
        assertThat(givenName.reason, Matchers.`is`("managed_by_identity_provider"))

        val nickname = policy["/nickname"]!!
        assertThat(nickname.access, Matchers.`is`(ProfileFieldAccess.READ_WRITE))
        assertThat(nickname.source, Matchers.`is`(ProfileFieldSource.USER))
        assertThat(nickname.reason, Matchers.nullValue())

        assertThat(policy["/created_at"]!!.source, Matchers.`is`(ProfileFieldSource.SYSTEM))
    }

    @Test
    public fun `getUserProfile should map unknown policy values to null without failing`() {
        mockAPI.willReturnUserProfileWithUnknownPolicyValues()

        val policy = client.getUserProfile().execute().profilePolicy!!["/given_name"]!!

        assertThat(policy.access, Matchers.nullValue())
        assertThat(policy.source, Matchers.nullValue())
        assertThat(policy.reason, Matchers.`is`("some_new_reason"))
    }

    @Test
    public fun `getUserProfile should return null profilePolicy when it is not in the response`() {
        mockAPI.willReturnUserProfileWithoutPolicy()

        val profile = client.getUserProfile(GetUserProfileOptions(listOf("given_name", "picture")))
            .execute()

        assertThat(profile.givenName, Matchers.`is`("Jane"))
        assertThat(profile.profilePolicy, Matchers.nullValue())
    }

    @Test
    public fun `getUserProfile should send Bearer authorization and Auth0-Client headers`() {
        mockAPI.willReturnUserProfile()

        client.getUserProfile().execute()

        val request = mockAPI.takeRequest()
        assertThat(request.getHeader("Authorization"), Matchers.`is`("Bearer $ACCESS_TOKEN"))
        assertThat(request.getHeader("Auth0-Client"), Matchers.notNullValue())
        assertThat(request.getHeader("DPoP"), Matchers.nullValue())
    }

    @Test
    public fun `getUserProfile should send DPoP authorization and proof when DPoP is enabled`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(FakeECPrivateKey(), FakeECPublicKey()))
        mockAPI.willReturnUserProfile()

        MyAccountAPIClient(auth0, ACCESS_TOKEN).useDPoP(mockContext).getUserProfile().execute()

        val request = mockAPI.takeRequest()
        assertThat(request.getHeader("Authorization"), Matchers.`is`("DPoP $ACCESS_TOKEN"))
        assertThat(request.getHeader("DPoP"), Matchers.notNullValue())
    }

    @Test
    public fun `getUserProfile should return the profile through the callback`() {
        mockAPI.willReturnUserProfile()
        val callback = MockMyAccountCallback<MyAccountProfile>()

        client.getUserProfile().start(callback)

        awaitCallback(callback)
        assertThat(callback.getPayload()!!.givenName, Matchers.`is`("Jane"))
        assertThat(callback.getError(), Matchers.nullValue())
    }

    @Test
    public fun `getUserProfile should return the profile through await`(): Unit = runTest {
        mockAPI.willReturnUserProfile()

        val profile = client.getUserProfile().await()

        assertThat(profile.givenName, Matchers.`is`("Jane"))
    }

    // updateUserProfile

    @Test
    public fun `updateUserProfile should send a PATCH request with the set root fields only`() {
        mockAPI.willReturnUserProfile()

        client.updateUserProfile(
            UpdateUserProfileRequest(givenName = "Jane", nickname = "jane")
        ).execute()

        val request = mockAPI.takeRequest()
        assertThat(request.method, Matchers.`is`("PATCH"))
        assertThat(request.path, Matchers.`is`("/me/v1/profile"))
        val body = bodyFromRequest(request)
        assertThat(body, Matchers.`is`(mapOf<String, Any?>("given_name" to "Jane", "nickname" to "jane")))
    }

    @Test
    public fun `updateUserProfile should send every root field when set`() {
        mockAPI.willReturnUserProfile()

        client.updateUserProfile(
            UpdateUserProfileRequest(
                givenName = "Jane",
                familyName = "Doe",
                name = "Jane Doe",
                nickname = "jane",
                picture = "https://example.com/jane.png"
            )
        ).execute()

        val body = bodyFromRequest(mockAPI.takeRequest())
        assertThat(
            body, Matchers.`is`(
                mapOf<String, Any?>(
                    "given_name" to "Jane",
                    "family_name" to "Doe",
                    "name" to "Jane Doe",
                    "nickname" to "jane",
                    "picture" to "https://example.com/jane.png"
                )
            )
        )
    }

    @Test
    public fun `updateUserProfile should send an empty body for an empty request`() {
        mockAPI.willReturnUserProfile()

        client.updateUserProfile(UpdateUserProfileRequest()).execute()

        val request = mockAPI.takeRequest()
        assertThat(request.method, Matchers.`is`("PATCH"))
        assertThat(request.body.readUtf8(), Matchers.`is`("{}"))
    }

    @Test
    public fun `updateUserProfile should return the full profile`() {
        mockAPI.willReturnUserProfile()

        val profile = client.updateUserProfile(UpdateUserProfileRequest(givenName = "Jane"))
            .execute()

        assertThat(profile.email, Matchers.`is`("jane@example.com"))
        assertThat(profile.profilePolicy!!.size, Matchers.`is`(3))
    }

    @Test
    public fun `updateUserProfile should send Bearer authorization header`() {
        mockAPI.willReturnUserProfile()

        client.updateUserProfile(UpdateUserProfileRequest()).execute()

        val request = mockAPI.takeRequest()
        assertThat(request.getHeader("Authorization"), Matchers.`is`("Bearer $ACCESS_TOKEN"))
        assertThat(request.getHeader("DPoP"), Matchers.nullValue())
    }

    @Test
    public fun `updateUserProfile should send DPoP authorization and proof when DPoP is enabled`() {
        whenever(mockKeyStore.hasKeyPair()).thenReturn(true)
        whenever(mockKeyStore.getKeyPair()).thenReturn(Pair(FakeECPrivateKey(), FakeECPublicKey()))
        mockAPI.willReturnUserProfile()

        MyAccountAPIClient(auth0, ACCESS_TOKEN).useDPoP(mockContext)
            .updateUserProfile(UpdateUserProfileRequest(givenName = "Jane"))
            .execute()

        val request = mockAPI.takeRequest()
        assertThat(request.getHeader("Authorization"), Matchers.`is`("DPoP $ACCESS_TOKEN"))
        assertThat(request.getHeader("DPoP"), Matchers.notNullValue())
        assertThat(request.body.readUtf8(), Matchers.`is`("{\"given_name\":\"Jane\"}"))
    }

    @Test
    public fun `updateUserProfile should return the profile through await`(): Unit = runTest {
        mockAPI.willReturnUserProfile()

        val profile = client.updateUserProfile(UpdateUserProfileRequest(givenName = "Jane")).await()

        assertThat(profile.givenName, Matchers.`is`("Jane"))
    }

    // Errors

    @Test
    public fun `getUserProfile should surface the feature not enabled error`() {
        mockAPI.willReturnFeatureNotEnabledError()

        val error = executeForError { client.getUserProfile().execute() }

        assertThat(error.statusCode, Matchers.`is`(403))
        assertThat(error.getCode(), Matchers.`is`("Not Entitled"))
        assertThat(error.type, Matchers.`is`("https://auth0.com/api-errors/A0E-403-0003"))
        assertThat(error.detail, Matchers.`is`("This feature is currently not enabled"))
    }

    @Test
    public fun `updateUserProfile should surface the feature not enabled error`() {
        mockAPI.willReturnFeatureNotEnabledError()

        val error = executeForError {
            client.updateUserProfile(UpdateUserProfileRequest(givenName = "Jane")).execute()
        }

        assertThat(error.statusCode, Matchers.`is`(403))
        assertThat(error.getCode(), Matchers.`is`("Not Entitled"))
    }

    @Test
    public fun `getUserProfile should surface errors through the callback`() {
        mockAPI.willReturnFeatureNotEnabledError()
        val callback = MockMyAccountCallback<MyAccountProfile>()

        client.getUserProfile().start(callback)

        awaitCallback(callback)
        assertThat(callback.getError()!!.statusCode, Matchers.`is`(403))
        assertThat(callback.getPayload(), Matchers.nullValue())
    }

    @Test
    public fun `updateUserProfile should surface errors through await`(): Unit = runTest {
        mockAPI.willReturnFeatureNotEnabledError()

        val error = try {
            client.updateUserProfile(UpdateUserProfileRequest()).await()
            null
        } catch (e: MyAccountException) {
            e
        }

        assertThat(error!!.statusCode, Matchers.`is`(403))
    }

    @Test
    public fun `updateUserProfile should expose validation errors on 400`() {
        mockAPI.willReturnProfileValidationError()

        val error = executeForError {
            client.updateUserProfile(UpdateUserProfileRequest(givenName = "Jane")).execute()
        }

        assertThat(error.statusCode, Matchers.`is`(400))
        val validationError = error.validationErrors!!.single()
        assertThat(validationError.pointer, Matchers.`is`("/given_name"))
        assertThat(validationError.source, Matchers.`is`("managed_by_identity_provider"))
        assertThat(
            validationError.detail,
            Matchers.`is`("given_name is managed by the identity provider")
        )
    }

    @Test
    public fun `getUserProfile should surface 401 errors`() {
        mockAPI.willReturnUnauthorizedError()

        val error = executeForError { client.getUserProfile().execute() }

        assertThat(error.statusCode, Matchers.`is`(401))
        assertThat(error.title, Matchers.`is`("Unauthorized"))
    }

    @Test
    public fun `updateUserProfile should surface 403 errors`() {
        mockAPI.willReturnForbiddenError()

        val error = executeForError {
            client.updateUserProfile(UpdateUserProfileRequest(givenName = "Jane")).execute()
        }

        assertThat(error.statusCode, Matchers.`is`(403))
        assertThat(error.detail, Matchers.`is`("You do not have permission to perform this operation"))
    }

    @Test
    public fun `getUserProfile should surface network errors`() {
        mockAPI.shutdown()

        val error = executeForError { client.getUserProfile().execute() }

        assertThat(error.isNetworkError, Matchers.`is`(true))
    }

    private fun executeForError(block: () -> Unit): MyAccountException {
        try {
            block()
        } catch (e: MyAccountException) {
            return e
        }
        throw AssertionError("Expected a MyAccountException")
    }

    // The main looper can only be driven from the test thread, so poll here instead of Awaitility.
    private fun awaitCallback(callback: MockMyAccountCallback<*>) {
        val deadline = System.currentTimeMillis() + 5_000
        while (callback.getPayload() == null && callback.getError() == null) {
            if (System.currentTimeMillis() > deadline) {
                throw AssertionError("Callback was not invoked")
            }
            ShadowLooper.idleMainLooper()
            Thread.sleep(10)
        }
    }

    private fun bodyFromRequest(request: RecordedRequest): Map<String, Any?> {
        val mapType = object : TypeToken<Map<String, Any?>>() {}.type
        return Gson().fromJson(request.body.readUtf8(), mapType)
    }

    private val auth0: Auth0
        get() {
            val auth0 = Auth0.getInstance(CLIENT_ID, mockAPI.domain, mockAPI.domain)
            auth0.networkingClient = testClient
            return auth0
        }

    private companion object {
        private const val CLIENT_ID = "CLIENTID"
        private const val ACCESS_TOKEN = "accessToken"
    }
}
