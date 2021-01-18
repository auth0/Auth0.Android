package com.auth0.android.result

/**
 * The result of a successful authentication against Auth0
 * Contains the logged in user's [Credentials] and [UserProfile].
 *
 * @see [com.auth0.android.authentication.AuthenticationAPIClient.getProfileAfter]
 */
public class Authentication(public val profile: UserProfile, public val credentials: Credentials)