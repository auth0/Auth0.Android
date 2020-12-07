package com.auth0.android.request.kt

import android.net.Credentials
import android.net.Uri
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.request.internal.GsonProvider

public class AuthApi(
    private val account: Auth0,
    private val networkingClient: NetworkingClient = DefaultClient(account.connectTimeoutInSeconds)
) {

    private val gson = GsonProvider.buildGson()
    private val baseUri = Uri.parse(account.domainUrl)
    private val errorBuilder: ErrorBuilder<AuthenticationException> = DefaultErrorBuilder(gson)

    /**
     * Logs the user in using the "http://auth0.com/oauth/grant-type/password-realm" grant type.
     */
    public fun loginRealm(
        usernameOrEmail: String,
        password: String,
        realmOrConnection: String
    ): ImprovedRequest<Credentials, AuthenticationException> {
        val destinationUrl = baseUri.buildUpon()
            .appendPath("oauth")
            .appendPath("token")
            .build()

        return ImprovedRequest<Credentials, AuthenticationException>(
            HttpMethod.POST,
            destinationUrl.toString(),
            networkingClient,
            gson.getAdapter(Credentials::class.java),
            errorBuilder
        )
            .withParameter(ParameterBuilder.CLIENT_ID_KEY, account.clientId)
            .withParameter("username", usernameOrEmail)
            .withParameter("password", password)
            .withParameter(ParameterBuilder.REALM_KEY, realmOrConnection)
            .withParameter(
                ParameterBuilder.GRANT_TYPE_KEY,
                ParameterBuilder.GRANT_TYPE_PASSWORD_REALM
            )
    }
}