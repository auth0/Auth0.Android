package com.auth0.android.myaccount.request

/**
 * The changes to apply with [com.auth0.android.myaccount.MyAccountAPIClient.updateUserProfile].
 *
 * Properties left as `null` are not sent and remain unchanged. A request with every property
 * `null` is valid and returns the current profile.
 *
 * @param givenName the user's given name
 * @param familyName the user's family name
 * @param name the user's full name
 * @param nickname the user's nickname
 * @param picture the URL of the user's picture
 */
public data class UpdateUserProfileRequest @JvmOverloads constructor(
    public val givenName: String? = null,
    public val familyName: String? = null,
    public val name: String? = null,
    public val nickname: String? = null,
    public val picture: String? = null
)
