package com.auth0.android.management

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.Request
import com.auth0.android.request.internal.BaseRequest
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forListOf
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.auth0.android.result.UserIdentity
import com.auth0.android.result.UserProfile
import com.google.gson.Gson
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader

/**
 * API client for Auth0 Management API.
 * ```
 * val auth0 = Auth0("your_client_id", "your_domain")
 * val client = UsersAPIClient(auth0)
 * ```
 *
 * @see [Auth API docs](https://auth0.com/docs/api/management/v2)
 */
public class UsersAPIClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val factory: RequestFactory<ManagementException>,
    private val gson: Gson
) {
    /**
     * Creates a new API client instance providing the Auth0 account info and the access token.
     *
     * @param auth0            account information
     * @param token            of the primary identity
     */
    public constructor(
        auth0: Auth0,
        token: String
    ) : this(
        auth0,
        factoryForToken(token, auth0.networkingClient),
        GsonProvider.gson
    )

    public val clientId: String
        get() = auth0.clientId
    public val baseURL: String
        get() = auth0.getDomainUrl()

    /**
     * Link a user identity calling ['/api/v2/users/:primaryUserId/identities'](https://auth0.com/docs/link-accounts#the-management-api) endpoint
     * Example usage:
     * ```
     * client.link("{auth0 primary user id}", "{user secondary token}")
     *     .start(object: Callback<List<UserIdentity>, ManagementException> {
     *         override fun onSuccess(result: List<UserIdentity>) { }
     *         override fun onFailure(error: ManagementException) { }
     * })
     * ```
     *
     * @param primaryUserId  of the identity to link
     * @param secondaryToken of the secondary identity obtained after login
     * @return a request to start
     */
    public fun link(
        primaryUserId: String,
        secondaryToken: String
    ): Request<List<UserIdentity>, ManagementException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(API_PATH)
            .addPathSegment(V2_PATH)
            .addPathSegment(USERS_PATH)
            .addPathSegment(primaryUserId)
            .addPathSegment(IDENTITIES_PATH)
            .build()
        val parameters = ParameterBuilder.newBuilder()
            .set(LINK_WITH_KEY, secondaryToken)
            .asDictionary()
        val userIdentitiesAdapter: JsonAdapter<List<UserIdentity>> = forListOf(
            UserIdentity::class.java, gson
        )
        return factory.post(url.toString(), userIdentitiesAdapter)
            .addParameters(parameters)
    }

    /**
     * Unlink a user identity calling ['/api/v2/users/:primaryToken/identities/secondaryProvider/secondaryUserId'](https://auth0.com/docs/link-accounts#unlinking-accounts) endpoint
     * Example usage:
     * ```
     * client.unlink("{auth0 primary user id}", {auth0 secondary user id}, "{secondary provider}")
     *     .start(object: Callback<List<UserIdentity>, ManagementException> {
     *         override fun onSuccess(result: List<UserIdentity>) { }
     *         override fun onFailure(error: ManagementException) {}
     * })
     * ```
     *
     * @param primaryUserId     of the primary identity to unlink
     * @param secondaryUserId   of the secondary identity you wish to unlink from the main one.
     * @param secondaryProvider of the secondary identity you wish to unlink from the main one.
     * @return a request to start
     */
    public fun unlink(
        primaryUserId: String,
        secondaryUserId: String,
        secondaryProvider: String
    ): Request<List<UserIdentity>, ManagementException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(API_PATH)
            .addPathSegment(V2_PATH)
            .addPathSegment(USERS_PATH)
            .addPathSegment(primaryUserId)
            .addPathSegment(IDENTITIES_PATH)
            .addPathSegment(secondaryProvider)
            .addPathSegment(secondaryUserId)
            .build()
        val userIdentitiesAdapter: JsonAdapter<List<UserIdentity>> = forListOf(
            UserIdentity::class.java, gson
        )
        return factory.delete(url.toString(), userIdentitiesAdapter)
    }

    /**
     * Update the user_metadata calling ['/api/v2/users/:userId'](https://auth0.com/docs/api/management/v2#!/Users/patch_users_by_id) endpoint
     * Example usage:
     * ```
     * client.updateMetadata("{user id}", "{user metadata}")
     *     .start(object: Callback<UserProfile, ManagementException> {
     *         override fun onSuccess(result: UserProfile) { }
     *         override fun onFailure(error: ManagementException) { }
     * })
     * ```
     *
     * @param userId       of the primary identity to unlink
     * @param userMetadata to merge with the existing one
     * @return a request to start
     */
    public fun updateMetadata(
        userId: String,
        userMetadata: Map<String, Any?>
    ): Request<UserProfile, ManagementException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(API_PATH)
            .addPathSegment(V2_PATH)
            .addPathSegment(USERS_PATH)
            .addPathSegment(userId)
            .build()
        val userProfileAdapter: JsonAdapter<UserProfile> = GsonAdapter(
            UserProfile::class.java, gson
        )
        val patch = factory.patch(
            url.toString(),
            userProfileAdapter
        ) as BaseRequest<UserProfile, ManagementException>
        patch.addParameter(USER_METADATA_KEY, userMetadata)
        return patch
    }

    /**
     * Get the User Profile calling ['/api/v2/users/:userId'](https://auth0.com/docs/api/management/v2#!/Users/get_users_by_id) endpoint
     * Example usage:
     * ```
     * client.getProfile("{user id}")
     *     .start(object: Callback<UserProfile, ManagementException> {
     *         override fun onSuccess(result: UserProfile) { }
     *         override fun onFailure(error: ManagementException) { }
     * })
     * ```
     *
     * @param userId identity of the user
     * @return a request to start
     */
    public fun getProfile(userId: String): Request<UserProfile, ManagementException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(API_PATH)
            .addPathSegment(V2_PATH)
            .addPathSegment(USERS_PATH)
            .addPathSegment(userId)
            .build()
        val userProfileAdapter: JsonAdapter<UserProfile> = GsonAdapter(
            UserProfile::class.java, gson
        )
        return factory.get(url.toString(), userProfileAdapter)
    }

    private companion object {
        private const val LINK_WITH_KEY = "link_with"
        private const val API_PATH = "api"
        private const val V2_PATH = "v2"
        private const val USERS_PATH = "users"
        private const val IDENTITIES_PATH = "identities"
        private const val USER_METADATA_KEY = "user_metadata"

        private fun createErrorAdapter(): ErrorAdapter<ManagementException> {
            val mapAdapter = forMap(GsonProvider.gson)
            return object : ErrorAdapter<ManagementException> {
                override fun fromRawResponse(
                    statusCode: Int,
                    bodyText: String,
                    headers: Map<String, List<String>>
                ): ManagementException {
                    return ManagementException(bodyText, statusCode)
                }

                @Throws(IOException::class)
                override fun fromJsonResponse(
                    statusCode: Int,
                    reader: Reader
                ): ManagementException {
                    val values = mapAdapter.fromJson(reader)
                    return ManagementException(values)
                }

                override fun fromException(cause: Throwable): ManagementException {
                    if (isNetworkError(cause)) {
                        return ManagementException(
                            "Failed to execute the network request",
                            NetworkErrorException(cause)
                        )
                    }
                    return ManagementException(
                        "Something went wrong",
                        Auth0Exception("Something went wrong", cause)
                    )
                }
            }
        }

        private fun factoryForToken(
            token: String,
            client: NetworkingClient
        ): RequestFactory<ManagementException> {
            val factory = RequestFactory(client, createErrorAdapter())
            factory.setHeader("Authorization", "Bearer $token")
            return factory
        }
    }

    init {
        factory.setAuth0ClientInfo(auth0.auth0UserAgent.value)
    }
}