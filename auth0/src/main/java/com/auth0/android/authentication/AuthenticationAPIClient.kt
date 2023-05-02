package com.auth0.android.authentication

import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.request.*
import com.auth0.android.request.internal.*
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonAdapter.Companion.forMapOf
import com.auth0.android.result.Challenge
import com.auth0.android.result.Credentials
import com.auth0.android.result.DatabaseUser
import com.auth0.android.result.UserProfile
import com.google.gson.Gson
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader
import java.security.PublicKey

/**
 * API client for Auth0 Authentication API.
 * ```
 * val auth0 = Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 * val client = AuthenticationAPIClient(auth0)
 * ```
 *
 * @see [Auth API docs](https://auth0.com/docs/auth-api)
 */
public class AuthenticationAPIClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val factory: RequestFactory<AuthenticationException>,
    private val gson: Gson
) {

    /**
     * Creates a new API client instance providing Auth0 account info.
     *
     * Example usage:
     *
     * ```
     * val auth0 = Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN")
     * val client = AuthenticationAPIClient(auth0)
     * ```
     * @param auth0 account information
     */
    public constructor(auth0: Auth0) : this(
        auth0,
        RequestFactory<AuthenticationException>(auth0.networkingClient, createErrorAdapter()),
        GsonProvider.gson
    )

    public val clientId: String
        get() = auth0.clientId
    public val baseURL: String
        get() = auth0.getDomainUrl()

    /**
     * Log in a user with email/username and password for a connection/realm.
     * It will use the password-realm grant type for the `/oauth/token` endpoint
     * The default scope used is 'openid profile email'.
     *
     * Example usage:
     *
     * ```
     * client
     *     .login("{username or email}", "{password}", "{database connection name}")
     *     .validateClaims() //mandatory
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     *```
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
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .set(USERNAME_KEY, usernameOrEmail)
            .set(PASSWORD_KEY, password)
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORD_REALM)
            .setRealm(realmOrConnection)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Log in a user with email/username and password using the password grant and the default directory.
     * The default scope used is 'openid profile email'.
     *
     * Example usage:
     *
     * ```
     * client.login("{username or email}", "{password}")
     *     .validateClaims() //mandatory
     *     .start(object:  Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     *```
     *
     * @param usernameOrEmail of the user
     * @param password        of the user
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun login(usernameOrEmail: String, password: String): AuthenticationRequest {
        val requestParameters = ParameterBuilder.newAuthenticationBuilder()
            .set(USERNAME_KEY, usernameOrEmail)
            .set(PASSWORD_KEY, password)
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORD)
            .asDictionary()
        return loginWithToken(requestParameters)
    }

    /**
     * Log in a user using the One Time Password code after they have received the 'mfa_required' error.
     * The MFA token tells the server the username or email, password, and realm values sent on the first request.
     *
     * Requires your client to have the **MFA OTP** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.
     *
     * Example usage:
     *
     *```
     * client.loginWithOTP("{mfa token}", "{one time password}")
     *     .validateClaims() //mandatory
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onFailure(error: AuthenticationException) { }
     *         override fun onSuccess(result: Credentials) { }
     * })
     *```
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
     * Log in a user using an Out Of Band authentication code after they have received the 'mfa_required' error.
     * The MFA token tells the server the username or email, password, and realm values sent on the first request.
     *
     * Requires your client to have the **MFA OOB** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.
     *
     * Example usage:
     *
     *```
     * client.loginWithOOB("{mfa token}", "{out of band code}", "{binding code}")
     *     .validateClaims() //mandatory
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onFailure(error: AuthenticationException) { }
     *         override fun onSuccess(result: Credentials) { }
     * })
     *```
     *
     * @param mfaToken the token received in the previous [.login] response.
     * @param oobCode the out of band code received in the challenge response.
     * @param bindingCode the code used to bind the side channel (used to deliver the challenge) with the main channel you are using to authenticate.
     * This is usually an OTP-like code delivered as part of the challenge message.
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun loginWithOOB(
        mfaToken: String,
        oobCode: String,
        bindingCode: String? = null
    ): AuthenticationRequest {
        val parameters = ParameterBuilder.newBuilder()
            .setGrantType(ParameterBuilder.GRANT_TYPE_MFA_OOB)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(OUT_OF_BAND_CODE_KEY, oobCode)
            .set(BINDING_CODE_KEY, bindingCode)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Log in a user using a multi-factor authentication Recovery Code after they have received the 'mfa_required' error.
     * The MFA token tells the server the username or email, password, and realm values sent on the first request.
     *
     * Requires your client to have the **MFA** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.
     *
     * Example usage:
     *
     *```
     * client.loginWithRecoveryCode("{mfa token}", "{recovery code}")
     *     .validateClaims() //mandatory
     *     .start(object : Callback<Credentials, AuthenticationException> {
     *         override fun onFailure(error: AuthenticationException) { }
     *         override fun onSuccess(result: Credentials) { }
     * })
     *```
     *
     * @param mfaToken the token received in the previous [.login] response.
     * @param recoveryCode the recovery code provided by the end-user.
     * @return a request to configure and start that will yield [Credentials]. It might also include a [recoveryCode] field,
     * which your application must display to the end-user to be stored securely for future use.
     */
    public fun loginWithRecoveryCode(
        mfaToken: String,
        recoveryCode: String
    ): AuthenticationRequest {
        val parameters = ParameterBuilder.newBuilder()
            .setGrantType(ParameterBuilder.GRANT_TYPE_MFA_RECOVERY_CODE)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(RECOVERY_CODE_KEY, recoveryCode)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Request a challenge for multi-factor authentication (MFA) based on the challenge types supported by the application and user.
     * The challenge type is how the user will get the challenge and prove possession. Supported challenge types include: "otp" and "oob".
     *
     * Example usage:
     *
     *```
     * client.multifactorChallenge("{mfa token}", "{challenge type}", "{authenticator id}")
     *     .start(object : Callback<Challenge, AuthenticationException> {
     *         override fun onFailure(error: AuthenticationException) { }
     *         override fun onSuccess(result: Challenge) { }
     * })
     *```
     *
     * @param mfaToken the token received in the previous [.login] response.
     * @param challengeType A whitespace-separated list of the challenges types accepted by your application.
     * Accepted challenge types are oob or otp. Excluding this parameter means that your client application
     * accepts all supported challenge types.
     * @param authenticatorId The ID of the authenticator to challenge.
     * @return a request to configure and start that will yield [Challenge]
     */
    public fun multifactorChallenge(
        mfaToken: String,
        challengeType: String? = null,
        authenticatorId: String? = null
    ): Request<Challenge, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .set(MFA_TOKEN_KEY, mfaToken)
            .set(CHALLENGE_TYPE_KEY, challengeType)
            .set(AUTHENTICATOR_ID_KEY, authenticatorId)
            .asDictionary()
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(MFA_PATH)
            .addPathSegment(CHALLENGE_PATH)
            .build()
        val challengeAdapter: JsonAdapter<Challenge> = GsonAdapter(
            Challenge::class.java, gson
        )
        return factory.post(url.toString(), challengeAdapter)
            .addParameters(parameters)
    }

    /**
     * Log in a user using a token obtained from a Native Social Identity Provider, such as Facebook, using ['\oauth\token' endpoint](https://auth0.com/docs/api/authentication#token-exchange-for-native-social)
     * The default scope used is 'openid profile email'.
     *
     * Example usage:
     *
     * ```
     * client.loginWithNativeSocialToken("{subject token}", "{subject token type}")
     *     .validateClaims() //mandatory
     *     .start(object: Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param token     the subject token, typically obtained through the Identity Provider's SDK
     * @param tokenType the subject token type that is associated with this Identity Provider. e.g. 'http://auth0.com/oauth/token-type/facebook-session-access-token'
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun loginWithNativeSocialToken(token: String, tokenType: String): AuthenticationRequest {
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setGrantType(ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE)
            .setClientId(clientId)
            .set(SUBJECT_TOKEN_KEY, token)
            .set(SUBJECT_TOKEN_TYPE_KEY, tokenType)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Log in a user using a phone number and a verification code received via SMS (Part of passwordless login flow)
     * The default scope used is 'openid profile email'.
     *
     * Your Application must have the **Passwordless OTP** Grant Type enabled.
     *
     * Example usage:
     * ```
     * client.loginWithPhoneNumber("{phone number}", "{code}", "{passwordless connection name}")
     *     .validateClaims() //mandatory
     *     .start(object: Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
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
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setClientId(clientId)
            .set(USERNAME_KEY, phoneNumber)
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
            .set(ONE_TIME_PASSWORD_KEY, verificationCode)
            .setRealm(realmOrConnection)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Log in a user using an email and a verification code received via Email (Part of passwordless login flow).
     * The default scope used is 'openid profile email'.
     *
     * Your Application must have the **Passwordless OTP** Grant Type enabled.
     *
     * Example usage:
     * ```
     * client.loginWithEmail("{email}", "{code}", "{passwordless connection name}")
     *     .validateClaims() //mandatory
     *     .start(object: Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     *```
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
        val parameters = ParameterBuilder.newAuthenticationBuilder()
            .setClientId(clientId)
            .set(USERNAME_KEY, email)
            .setGrantType(ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP)
            .set(ONE_TIME_PASSWORD_KEY, verificationCode)
            .setRealm(realmOrConnection)
            .asDictionary()
        return loginWithToken(parameters)
    }

    /**
     * Returns the information of the user associated with the given access_token.
     *
     * Example usage:
     * ```
     * client.userInfo("{access_token}")
     *     .start(object: Callback<UserProfile, AuthenticationException> {
     *         override fun onSuccess(result: UserProfile) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     *```
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
     *
     * Example usage:
     * ```
     * client.createUser("{email}", "{password}", "{username}", "{database connection name}")
     *     .start(object: Callback<DatabaseUser, AuthenticationException> {
     *         override fun onSuccess(result: DatabaseUser) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param username   of the user and must be non null
     * @param connection of the database to create the user on
     * @param userMetadata to set upon creation of the user
     * @return a request to start
     */
    @JvmOverloads
    public fun createUser(
        email: String,
        password: String,
        username: String? = null,
        connection: String,
        userMetadata: Map<String, String>? = null
    ): Request<DatabaseUser, AuthenticationException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
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
        val post = factory.post(url.toString(), databaseUserAdapter)
            .addParameters(parameters) as BaseRequest<DatabaseUser, AuthenticationException>
        userMetadata?.let { post.addParameter(USER_METADATA_KEY, userMetadata) }
        return post
    }

    /**
     * Creates a user in a DB connection using ['/dbconnections/signup' endpoint](https://auth0.com/docs/api/authentication#signup)
     * and then logs in the user.
     * The default scope used is 'openid profile email'.
     *
     * Example usage:
     *
     * ```
     * client.signUp("{email}", "{password}", "{username}", "{database connection name}")
     *     .validateClaims() //mandatory
     *     .start(object: Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     *```
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param username   of the user and must be non null
     * @param connection of the database to sign up with
     * @param userMetadata to set upon creation of the user
     * @return a request to configure and start that will yield [Credentials]
     */
    @JvmOverloads
    public fun signUp(
        email: String,
        password: String,
        username: String? = null,
        connection: String,
        userMetadata: Map<String, String>? = null
    ): SignUpRequest {
        val createUserRequest = createUser(email, password, username, connection, userMetadata)
        val authenticationRequest = login(email, password, connection)
        return SignUpRequest(createUserRequest, authenticationRequest)
    }

    /**
     * Request a reset password using ['/dbconnections/change_password'](https://auth0.com/docs/api/authentication#change-password)
     *
     * Example usage:
     *
     * ```
     * client.resetPassword("{email}", "{database connection name}")
     *     .start(object: Callback<Void?, AuthenticationException> {
     *         override fun onSuccess(result: Void?) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param email      of the user to request the password reset. An email will be sent with the reset instructions.
     * @param connection of the database to request the reset password on
     * @return a request to configure and start
     */
    public fun resetPassword(
        email: String,
        connection: String
    ): Request<Void?, AuthenticationException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
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
     *
     * Example usage:
     *
     * ```
     * client.revokeToken("{refresh_token}")
     *     .start(object: Callback<Void?, AuthenticationException> {
     *         override fun onSuccess(result: Void?) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param refreshToken the token to revoke
     * @return a request to start
     */
    public fun revokeToken(refreshToken: String): Request<Void?, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .set(TOKEN_KEY, refreshToken)
            .asDictionary()
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(REVOKE_PATH)
            .build()
        return factory.post(url.toString())
            .addParameters(parameters)
    }

    /**
     * Requests new Credentials using a valid Refresh Token. The received token will have the same audience and scope as first requested.
     *
     * This method will use the /oauth/token endpoint with the 'refresh_token' grant, and the response will include an id_token and an access_token if 'openid' scope was requested when the refresh_token was obtained.
     * Additionally, if the application has Refresh Token Rotation configured, a new one-time use refresh token will also be included in the response.
     *
     * The scope of the newly received Access Token can be reduced sending the scope parameter with this request.
     *
     * Example usage:
     * ```
     * client.renewAuth("{refresh_token}")
     *     .addParameter("scope", "openid profile email")
     *     .start(object: Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param refreshToken used to fetch the new Credentials.
     * @return a request to start
     */
    public fun renewAuth(refreshToken: String): Request<Credentials, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilderWithRequiredScope()
            .setClientId(clientId)
            .setRefreshToken(refreshToken)
            .setGrantType(ParameterBuilder.GRANT_TYPE_REFRESH_TOKEN)
            .asDictionary()
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
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
     *
     * Your Application must have the **Passwordless OTP** Grant Type enabled.
     *
     * Example usage:
     * ```
     * client.passwordlessWithEmail("{email}", PasswordlessType.CODE, "{passwordless connection name}")
     *     .start(object: Callback<Void?, AuthenticationException> {
     *         override onSuccess(result: Void?) { }
     *         override onFailure(error: AuthenticationException) { }
     * })
     * ```
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
    ): Request<Void?, AuthenticationException> {
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
     *
     * Your Application requires to have the **Passwordless OTP** Grant Type enabled.
     *
     * Example usage:
     * ```
     * client.passwordlessWithSms("{phone number}", PasswordlessType.CODE, "{passwordless connection name}")
     *     .start(object: Callback<Void?, AuthenticationException> {
     *         override fun onSuccess(result: Void?) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
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
    ): Request<Void?, AuthenticationException> {
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
    private fun passwordless(): Request<Void?, AuthenticationException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
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
     * @return a [ProfileRequest] that first logs in and then fetches the profile
     */
    public fun getProfileAfter(authenticationRequest: AuthenticationRequest): ProfileRequest {
        return ProfileRequest(authenticationRequest, profileRequest())
    }

    /**
     * Fetch the token information from Auth0, using the authorization_code grant type
     * The authorization code received from the Auth0 server and the code verifier used
     * to generate the challenge sent to the /authorize call must be provided.
     *
     * Example usage:
     *
     * ```
     * client
     *     .token("authorization code", "code verifier", "redirect_uri")
     *     .start(object: Callback<Credentials, AuthenticationException> {...})
     * ```
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
        val parameters = ParameterBuilder.newBuilderWithRequiredScope()
            .setClientId(clientId)
            .setGrantType(ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE)
            .set(OAUTH_CODE_KEY, authorizationCode)
            .set(REDIRECT_URI_KEY, redirectUri)
            .set("code_verifier", codeVerifier)
            .asDictionary()
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
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
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(WELL_KNOWN_PATH)
            .addPathSegment(JWKS_FILE_PATH)
            .build()
        val jwksAdapter: JsonAdapter<Map<String, PublicKey>> = forMapOf(
            PublicKey::class.java, gson
        )
        return factory.get(url.toString(), jwksAdapter)
    }

    /**
     * Helper function to make a request to the /oauth/token endpoint.
     */
    private fun loginWithToken(parameters: Map<String, String>): AuthenticationRequest {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
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
        val request = BaseAuthenticationRequest(factory.post(url.toString(), credentialsAdapter), clientId, baseURL)
        request.addParameters(requestParameters)
        return request
    }

    private fun profileRequest(): Request<UserProfile, AuthenticationException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
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
        private const val OUT_OF_BAND_CODE_KEY = "oob_code"
        private const val BINDING_CODE_KEY = "binding_code"
        private const val CHALLENGE_TYPE_KEY = "challenge_type"
        private const val AUTHENTICATOR_ID_KEY = "authenticator_id"
        private const val RECOVERY_CODE_KEY = "recovery_code"
        private const val SUBJECT_TOKEN_KEY = "subject_token"
        private const val SUBJECT_TOKEN_TYPE_KEY = "subject_token_type"
        private const val USER_METADATA_KEY = "user_metadata"
        private const val SIGN_UP_PATH = "signup"
        private const val DB_CONNECTIONS_PATH = "dbconnections"
        private const val CHANGE_PASSWORD_PATH = "change_password"
        private const val PASSWORDLESS_PATH = "passwordless"
        private const val START_PATH = "start"
        private const val OAUTH_PATH = "oauth"
        private const val TOKEN_PATH = "token"
        private const val USER_INFO_PATH = "userinfo"
        private const val REVOKE_PATH = "revoke"
        private const val MFA_PATH = "mfa"
        private const val CHALLENGE_PATH = "challenge"
        private const val HEADER_AUTHORIZATION = "Authorization"
        private const val WELL_KNOWN_PATH = ".well-known"
        private const val JWKS_FILE_PATH = "jwks.json"
        private fun createErrorAdapter(): ErrorAdapter<AuthenticationException> {
            val mapAdapter = forMap(GsonProvider.gson)
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
        factory.setAuth0ClientInfo(auth0UserAgent.value)
    }
}