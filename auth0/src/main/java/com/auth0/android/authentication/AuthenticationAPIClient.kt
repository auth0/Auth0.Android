/*
 * AuthenticationAPIClient.java
 *
 * Copyright (c) 2015 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.auth0.android.authentication

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.request.ProfileRequest
import com.auth0.android.authentication.request.SignUpRequest
import com.auth0.android.request.*
import com.auth0.android.request.internal.BaseAuthenticationRequest
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonAdapter.Companion.forMapOf
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.result.Credentials
import com.auth0.android.result.DatabaseUser
import com.auth0.android.result.UserProfile
import com.google.gson.Gson
import com.squareup.okhttp.HttpUrl
import java.io.IOException
import java.io.Reader
import java.security.PublicKey

/**
 * API client for Auth0 Authentication API.
 * <pre>
 * `Auth0 auth0 = new Auth0("your_client_id", "your_domain");
 * AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);
` *
</pre> *
 *
 * @see [Auth API docs](https://auth0.com/docs/auth-api)
 */
public class AuthenticationAPIClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val factory: RequestFactory<AuthenticationException>,
    private val gson: Gson
) {

    /**
     * Creates a new API client instance providing Auth0 account info and a custom Networking Client.
     *
     * @param auth0            account information
     * @param networkingClient the networking client implementation
     */
    @JvmOverloads
    public constructor(
        auth0: Auth0,
        networkingClient: NetworkingClient = DefaultClient(auth0.connectTimeoutInSeconds)
    ) : this(
        auth0,
        RequestFactory<AuthenticationException>(networkingClient, createErrorAdapter()),
        GsonProvider.buildGson()
    )

    public val clientId: String
        get() = auth0.clientId
    public val baseURL: String
        get() = auth0.getDomainUrl()

    /**
     * Set the value of 'User-Agent' header for every request to Auth0 Authentication API
     *
     * @param userAgent value to send in every request to Auth0
     */
    public fun setUserAgent(userAgent: String) {
        factory.setUserAgent(userAgent)
    }

    /**
     * Log in a user with email/username and password for a connection/realm.
     * It will use the password-realm grant type for the `/oauth/token` endpoint
     * Example:
     * <pre>
     * `client
     * .login("{username or email}", "{password}", "{database connection name}")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) { }
     *
     * {}Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param usernameOrEmail   of the user depending of the type of DB connection
     * @param password          of the user
     * @param realmOrConnection realm to use in the authorize flow or the name of the database to authenticate with.
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun login(
        usernameOrEmail: String,
        password: String,
        realmOrConnection: String
    ): AuthenticationRequest {
        val builder = ParameterBuilder.newBuilder()
            .set(USERNAME_KEY, usernameOrEmail)
            .set(PASSWORD_KEY, password)
        val parameters = builder
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORD_REALM)
            .setRealm(realmOrConnection)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Log in a user with email/username and password using the password grant and the default directory
     * Example usage:
     * <pre>
     * `client.login("{username or email}", "{password}")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) { }
     *
     * {}Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param usernameOrEmail of the user
     * @param password        of the user
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun login(usernameOrEmail: String, password: String): AuthenticationRequest {
        val requestParameters = ParameterBuilder.newBuilder()
            .set(USERNAME_KEY, usernameOrEmail)
            .set(PASSWORD_KEY, password)
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORD)
            .asDictionary()
        return loginWithToken(requestParameters)
    }

    /**
     * Log in a user using the One Time Password code after they have received the 'mfa_required' error.
     * The MFA token tells the server the username or email, password and realm values sent on the first request.
     * Requires your client to have the **MFA** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.* Example usage:
     * <pre>
     * `client.loginWithOTP("{mfa token}", "{one time password}")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) { }
     *
     * {}Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param mfaToken the token received in the previous [.login] response.
     * @param otp      the one time password code provided by the resource owner, typically obtained from an
     * MFA application such as Google Authenticator or Guardian.
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun loginWithOTP(mfaToken: String, otp: String): AuthenticationRequest {
        val parameters = ParameterBuilder.newBuilder()
            .setGrantType(ParameterBuilder.GRANT_TYPE_MFA_OTP)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(ONE_TIME_PASSWORD_KEY, otp)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Log in a user using a token obtained from a Native Social Identity Provider, such as Facebook, using ['\oauth\token' endpoint](https://auth0.com/docs/api/authentication#token-exchange-for-native-social)
     * The default scope used is 'openid'.
     * Example usage:
     * <pre>
     * `client.loginWithNativeSocialToken("{subject token}", "{subject token type}")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) { }
     *
     * {}Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param token     the subject token, typically obtained through the Identity Provider's SDK
     * @param tokenType the subject token type that is associated with this Identity Provider. e.g. 'http://auth0.com/oauth/token-type/facebook-session-access-token'
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun loginWithNativeSocialToken(token: String, tokenType: String): AuthenticationRequest {
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setGrantType(ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE)
            .setClientId(clientId)
            .set(SUBJECT_TOKEN_KEY, token)
            .set(SUBJECT_TOKEN_TYPE_KEY, tokenType)
            .asDictionary()
        val credentialsAdapter = GsonAdapter(
            Credentials::class.java, gson
        )
        val request = BaseAuthenticationRequest(factory.post(url.toString(), credentialsAdapter))
        request.addParameters(parameters)
        return request
    }

    /**
     * Log in a user using a phone number and a verification code received via SMS (Part of passwordless login flow)
     * The default scope used is 'openid'.
     *
     *
     * Your Application must have the **Passwordless OTP** Grant Type enabled.
     *
     *
     * Example usage:
     * <pre>
     * `client.loginWithPhoneNumber("{phone number}", "{code}", "{passwordless connection name}")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) { }
     *
     * {}@Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param phoneNumber       where the user received the verification code
     * @param verificationCode  sent by Auth0 via SMS
     * @param realmOrConnection to end the passwordless authentication on
     * @return a request to configure and start that will yield [Credentials]
     */
    @JvmOverloads
    public fun loginWithPhoneNumber(
        phoneNumber: String,
        verificationCode: String,
        realmOrConnection: String = SMS_CONNECTION
    ): AuthenticationRequest {
        val builder = ParameterBuilder.newAuthenticationBuilder()
            .setClientId(clientId)
            .set(USERNAME_KEY, phoneNumber)
        val parameters = builder
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
            .set(ONE_TIME_PASSWORD_KEY, verificationCode)
            .setRealm(realmOrConnection)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Log in a user using an email and a verification code received via Email (Part of passwordless login flow).
     * The default scope used is 'openid'.
     * Your Application must have the **Passwordless OTP** Grant Type enabled.
     * Example usage:
     * <pre>
     * `client.loginWithEmail("{email}", "{code}", "{passwordless connection name}")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) { }
     *
     * {}@Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param email             where the user received the verification code
     * @param verificationCode  sent by Auth0 via Email
     * @param realmOrConnection to end the passwordless authentication on
     * @return a request to configure and start that will yield [Credentials]
     */
    @JvmOverloads
    public fun loginWithEmail(
        email: String,
        verificationCode: String,
        realmOrConnection: String = EMAIL_CONNECTION
    ): AuthenticationRequest {
        val builder = ParameterBuilder.newAuthenticationBuilder()
            .setClientId(clientId)
            .set(USERNAME_KEY, email)
        val parameters = builder
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
            .set(ONE_TIME_PASSWORD_KEY, verificationCode)
            .setRealm(realmOrConnection)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Returns the information of the user associated with the given access_token.
     * Example usage:
     * <pre>
     * `client.userInfo("{access_token}")
     * .start(new Callback<UserProfile, AuthenticationException>() {
     * {}Override
     * public void onSuccess(UserProfile payload) { }
     *
     * {}@Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param accessToken used to fetch it's information
     * @return a request to start
     */
    public fun userInfo(accessToken: String): Request<UserProfile, AuthenticationException> {
        return profileRequest()
            .addHeader(HEADER_AUTHORIZATION, "Bearer $accessToken")
    }

    /**
     * Creates a user in a DB connection using ['/dbconnections/signup' endpoint](https://auth0.com/docs/api/authentication#signup)
     * Example usage:
     * <pre>
     * `client.createUser("{email}", "{password}", "{username}", "{database connection name}")
     * .start(new Callback<DatabaseUser, AuthenticationException>() {
     * {}Override
     * public void onSuccess(DatabaseUser payload) { }
     *
     * {}@Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param username   of the user and must be non null
     * @param connection of the database to create the user on
     * @return a request to start
     */
    @JvmOverloads
    public fun createUser(
        email: String,
        password: String,
        username: String? = null,
        connection: String
    ): Request<DatabaseUser, AuthenticationException> {
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(DB_CONNECTIONS_PATH)
            .addPathSegment(SIGN_UP_PATH)
            .build()
        val parameters = ParameterBuilder.newBuilder()
            .set(USERNAME_KEY, username)
            .set(EMAIL_KEY, email)
            .set(PASSWORD_KEY, password)
            .setConnection(connection)
            .setClientId(clientId)
            .asDictionary()
        val databaseUserAdapter: JsonAdapter<DatabaseUser> = GsonAdapter(
            DatabaseUser::class.java, gson
        )
        return factory.post(url.toString(), databaseUserAdapter)
            .addParameters(parameters)
    }

    /**
     * Creates a user in a DB connection using ['/dbconnections/signup' endpoint](https://auth0.com/docs/api/authentication#signup)
     * and then logs in the user.
     * Example usage:
     * <pre>
     * `client.signUp("{email}", "{password}", "{username}", "{database connection name}")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) {}
     *
     * {}Override
     * public void onFailure(AuthenticationException error) {}
     * });DefaultClient(auth0.connectTimeoutInSeconds)
    ` *
    </pre> *
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param username   of the user and must be non null
     * @param connection of the database to sign up with
     * @return a request to configure and start that will yield [Credentials]
     */
    @JvmOverloads
    public fun signUp(
        email: String,
        password: String,
        username: String? = null,
        connection: String
    ): SignUpRequest {
        val createUserRequest = createUser(email, password, username, connection)
        val authenticationRequest = login(email, password, connection)
        return SignUpRequest(createUserRequest, authenticationRequest)
    }

    /**
     * Request a reset password using ['/dbconnections/change_password'](https://auth0.com/docs/api/authentication#change-password)
     * Example usage:
     * <pre>
     * `client.resetPassword("{email}", "{database connection name}")
     * .start(new Callback<Void, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Void payload) {}
     *
     * {}Override
     * public void onFailure(AuthenticationException error) {}
     * });
    ` *
    </pre> *
     *
     * @param email      of the user to request the password reset. An email will be sent with the reset instructions.
     * @param connection of the database to request the reset password on
     * @return a request to configure and start
     */
    public fun resetPassword(
        email: String,
        connection: String
    ): Request<Void, AuthenticationException> {
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(DB_CONNECTIONS_PATH)
            .addPathSegment(CHANGE_PASSWORD_PATH)
            .build()
        val parameters = ParameterBuilder.newBuilder()
            .set(EMAIL_KEY, email)
            .setClientId(clientId)
            .setConnection(connection)
            .asDictionary()
        return factory.post(url.toString())
            .addParameters(parameters)
    }

    /**
     * Request the revoke of a given refresh_token. Once revoked, the refresh_token cannot be used to obtain new tokens.
     * Your Auth0 Application Type should be set to 'Native' and Token Endpoint Authentication Method must be set to 'None'.
     * Example usage:
     * <pre>
     * `client.revokeToken("{refresh_token}")
     * .start(new Callback<Void, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Void payload) {}
     *
     * {}Override
     * public void onFailure(AuthenticationException error) {}
     * });
    ` *
    </pre> *
     *
     * @param refreshToken the token to revoke
     * @return a request to start
     */
    public fun revokeToken(refreshToken: String): Request<Void, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .set(TOKEN_KEY, refreshToken)
            .asDictionary()
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(REVOKE_PATH)
            .build()
        return factory.post(url.toString())
            .addParameters(parameters)
    }

    /**
     * Requests new Credentials using a valid Refresh Token. The received token will have the same audience and scope as first requested.
     *
     *
     * This method will use the /oauth/token endpoint with the 'refresh_token' grant, and the response will include an id_token and an access_token if 'openid' scope was requested when the refresh_token was obtained.
     * Additionally, if the application has Refresh Token Rotation configured, a new one-time use refresh token will also be included in the response.
     * Example usage:
     * <pre>
     * `client.renewAuth("{refresh_token}")
     * .addParameter("scope", "openid profile email")
     * .start(new Callback<Credentials, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Credentials payload) { }
     *
     * {}@Override
     * public void onFailure(AuthenticationException error) { }
     * });
    ` *
    </pre> *
     *
     * @param refreshToken used to fetch the new Credentials.
     * @return a request to start
     */
    public fun renewAuth(refreshToken: String): Request<Credentials, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setRefreshToken(refreshToken)
            .setGrantType(ParameterBuilder.GRANT_TYPE_REFRESH_TOKEN)
            .asDictionary()
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val credentialsAdapter = GsonAdapter(
            Credentials::class.java, gson
        )
        return factory.post(url.toString(), credentialsAdapter)
            .addParameters(parameters)
    }

    /**
     * Start a passwordless flow with an [Email](https://auth0.com/docs/api/authentication#get-code-or-link).
     * Your Application must have the **Passwordless OTP** Grant Type enabled.
     * Example usage:
     * <pre>
     * `client.passwordlessWithEmail("{email}", PasswordlessType.CODE, "{passwordless connection name}")
     * .start(new Callback<Void, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Void payload) {}
     *
     * {}Override
     * public void onFailure(AuthenticationException error) {}
     * });
    ` *
    </pre> *
     *
     * @param email            that will receive a verification code to use for login
     * @param passwordlessType indicate whether the email should contain a code, link or magic link (android &amp; iOS)
     * @param connection       the passwordless connection to start the flow with.
     * @return a request to configure and start
     */
    @JvmOverloads
    public fun passwordlessWithEmail(
        email: String,
        passwordlessType: PasswordlessType,
        connection: String = EMAIL_CONNECTION
    ): Request<Void, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .set(EMAIL_KEY, email)
            .setSend(passwordlessType)
            .setConnection(connection)
            .asDictionary()
        return passwordless()
            .addParameters(parameters)
    }

    /**
     * Start a passwordless flow with a [SMS](https://auth0.com/docs/api/authentication#get-code-or-link)
     * Your Application requires to have the **Passwordless OTP** Grant Type enabled.
     * Example usage:
     * <pre>
     * `client.passwordlessWithSms("{phone number}", PasswordlessType.CODE, "{passwordless connection name}")
     * .start(new Callback<Void, AuthenticationException>() {
     * {}Override
     * public void onSuccess(Void payload) {}
     *
     * {}Override
     * public void onFailure(AuthenticationException error) {}
     * });
    ` *
    </pre> *
     *
     * @param phoneNumber      where an SMS with a verification code will be sent
     * @param passwordlessType indicate whether the SMS should contain a code, link or magic link (android &amp; iOS)
     * @param connection       the passwordless connection to start the flow with.
     * @return a request to configure and start
     */
    @JvmOverloads
    public fun passwordlessWithSMS(
        phoneNumber: String,
        passwordlessType: PasswordlessType,
        connection: String = SMS_CONNECTION
    ): Request<Void, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .set(PHONE_NUMBER_KEY, phoneNumber)
            .setSend(passwordlessType)
            .setConnection(connection)
            .asDictionary()
        return passwordless()
            .addParameters(parameters)
    }

    /**
     * Start a custom passwordless flow
     *
     * @return a request to configure and start
     */
    private fun passwordless(): Request<Void, AuthenticationException> {
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(PASSWORDLESS_PATH)
            .addPathSegment(START_PATH)
            .build()
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .asDictionary()
        return factory.post(url.toString())
            .addParameters(parameters)
    }

    /**
     * Fetch the user's profile after it's authenticated by a login request.
     * If the login request fails, the returned request will fail
     *
     * @param authenticationRequest that will authenticate a user with Auth0 and return a [Credentials]
     * @return a [ProfileRequest] that first logins and the fetches the profile
     */
    public fun getProfileAfter(authenticationRequest: AuthenticationRequest): ProfileRequest {
        val profileRequest = profileRequest()
        return ProfileRequest(authenticationRequest, profileRequest)
    }

    /**
     * Fetch the token information from Auth0, using the authorization_code grant type
     * The authorization code received from the Auth0 server and the code verifier used
     * to generate the challenge sent to the /authorize call must be provided.
     * <pre>
     * `AuthenticationAPIClient client = new AuthenticationAPIClient(new Auth0("clientId", "domain"));
     * client
     * .token("authorization code", "code verifier", "redirect_uri")
     * .start(new Callback<Credentials> {...});
    ` *
    </pre> *
     *
     * @param authorizationCode the authorization code received from the /authorize call.
     * @param codeVerifier      the code verifier used to generate the code challenge sent to /authorize.
     * @param redirectUri       the uri sent to /authorize as the 'redirect_uri'.
     * @return a request to obtain access_token by exchanging an authorization code.
     */
    public fun token(
        authorizationCode: String,
        codeVerifier: String,
        redirectUri: String
    ): Request<Credentials, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE)
            .set(OAUTH_CODE_KEY, authorizationCode)
            .set(REDIRECT_URI_KEY, redirectUri)
            .set("code_verifier", codeVerifier)
            .asDictionary()
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val credentialsAdapter: JsonAdapter<Credentials> = GsonAdapter(
            Credentials::class.java, gson
        )
        val request = factory.post(url.toString(), credentialsAdapter)
        request.addParameters(parameters)
        return request
    }

    /**
     * Creates a new Request to obtain the JSON Web Keys associated with the Auth0 account under the given domain.
     * Only supports RSA keys used for signatures (Public Keys).
     *
     * @return a request to obtain the JSON Web Keys associated with this Auth0 account.
     */
    public fun fetchJsonWebKeys(): Request<Map<String, PublicKey>, AuthenticationException> {
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(WELL_KNOWN_PATH)
            .addPathSegment(JWKS_FILE_PATH)
            .build()
        val jwksAdapter: JsonAdapter<Map<String, PublicKey>> = forMapOf(
            PublicKey::class.java, gson
        )
        return factory.get(url.toString(), jwksAdapter)
    }

    private fun loginWithToken(parameters: Map<String, String>): AuthenticationRequest {
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val requestParameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .addAll(parameters)
            .asDictionary()
        val credentialsAdapter: JsonAdapter<Credentials> = GsonAdapter(
            Credentials::class.java, gson
        )
        val request = BaseAuthenticationRequest(factory.post(url.toString(), credentialsAdapter))
        request.addParameters(requestParameters)
        return request
    }

    private fun profileRequest(): Request<UserProfile, AuthenticationException> {
        val url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
            .addPathSegment(USER_INFO_PATH)
            .build()
        val userProfileAdapter: JsonAdapter<UserProfile> = GsonAdapter(
            UserProfile::class.java, gson
        )
        return factory.get(url.toString(), userProfileAdapter)
    }

    private companion object {
        private const val SMS_CONNECTION = "sms"
        private const val EMAIL_CONNECTION = "email"
        private const val USERNAME_KEY = "username"
        private const val PASSWORD_KEY = "password"
        private const val EMAIL_KEY = "email"
        private const val PHONE_NUMBER_KEY = "phone_number"
        private const val OAUTH_CODE_KEY = "code"
        private const val REDIRECT_URI_KEY = "redirect_uri"
        private const val TOKEN_KEY = "token"
        private const val MFA_TOKEN_KEY = "mfa_token"
        private const val ONE_TIME_PASSWORD_KEY = "otp"
        private const val SUBJECT_TOKEN_KEY = "subject_token"
        private const val SUBJECT_TOKEN_TYPE_KEY = "subject_token_type"
        private const val SIGN_UP_PATH = "signup"
        private const val DB_CONNECTIONS_PATH = "dbconnections"
        private const val CHANGE_PASSWORD_PATH = "change_password"
        private const val PASSWORDLESS_PATH = "passwordless"
        private const val START_PATH = "start"
        private const val OAUTH_PATH = "oauth"
        private const val TOKEN_PATH = "token"
        private const val USER_INFO_PATH = "userinfo"
        private const val REVOKE_PATH = "revoke"
        private const val HEADER_AUTHORIZATION = "Authorization"
        private const val WELL_KNOWN_PATH = ".well-known"
        private const val JWKS_FILE_PATH = "jwks.json"
        private fun createErrorAdapter(): ErrorAdapter<AuthenticationException> {
            val mapAdapter = forMap(Gson())
            return object : ErrorAdapter<AuthenticationException> {
                override fun fromRawResponse(
                    statusCode: Int,
                    bodyText: String,
                    headers: Map<String, List<String>>
                ): AuthenticationException {
                    return AuthenticationException(bodyText, statusCode)
                }

                @Throws(IOException::class)
                override fun fromJsonResponse(
                    statusCode: Int,
                    reader: Reader
                ): AuthenticationException {
                    val values = mapAdapter.fromJson(reader)
                    return AuthenticationException(values, statusCode)
                }

                override fun fromException(cause: Throwable): AuthenticationException {
                    return AuthenticationException(
                        "Something went wrong",
                        Auth0Exception("Something went wrong", cause)
                    )
                }
            }
        }
    }

    init {
        val auth0UserAgent = auth0.auth0UserAgent
        if (auth0UserAgent != null) {
            factory.setClientInfo(auth0UserAgent.value)
        }
    }
}