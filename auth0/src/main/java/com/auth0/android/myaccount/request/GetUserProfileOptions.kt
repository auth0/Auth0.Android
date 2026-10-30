package com.auth0.android.myaccount.request

/**
 * Options to control which fields are returned by
 * [com.auth0.android.myaccount.MyAccountAPIClient.getUserProfile].
 *
 * @param fields the fields to include in, or exclude from, the response, e.g.
 * `listOf("given_name", "picture", "profile_policy")`. When empty, the default set of fields is
 * returned.
 * @param includeFields whether [fields] are included (`true`, the default) or excluded (`false`)
 * from the response. Ignored when [fields] is empty.
 *
 * The returned profile's `profilePolicy` is only present when `profile_policy` is part of the
 * response:
 * - when [includeFields] is `true` and [fields] is not empty, only if [fields] contains `profile_policy`
 * - when [includeFields] is `false`, unless [fields] contains `profile_policy`
 */
public data class GetUserProfileOptions @JvmOverloads constructor(
    public val fields: List<String> = emptyList(),
    public val includeFields: Boolean = true
)
