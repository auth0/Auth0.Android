package com.auth0.android.myaccount

/**
 * Options to control which fields are returned by [MyAccountAPIClient.getUserProfile].
 *
 * @param fields the fields to include in (or exclude from) the response, e.g.
 * `listOf("given_name", "picture", "profile_policy")`. When set and `profile_policy` is not
 * included, the returned profile's `profilePolicy` will be null.
 * @param includeFields whether [fields] are included (`true`) or excluded (`false`) from the
 * response. Only sent when [fields] is not empty. Defaults to inclusion on the server.
 */
public data class GetUserProfileOptions @JvmOverloads constructor(
    public val fields: List<String>? = null,
    public val includeFields: Boolean? = null
)
