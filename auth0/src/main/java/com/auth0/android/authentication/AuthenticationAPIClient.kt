package com.auth0.android.authentication

import android.content.Context
import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0
import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.dpop.DPoP
import com.auth0.android.dpop.DPoPException
import com.auth0.android.dpop.SenderConstraining
import com.auth0.android.request.AuthenticationRequest
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.ProfileRequest
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.request.Request
import com.auth0.android.request.SignUpRequest
import com.auth0.android.request.UserData
import com.auth0.android.request.internal.BaseAuthenticationRequest
import com.auth0.android.request.internal.BaseRequest
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonAdapter.Companion.forMapOf
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.RequestFactory
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.auth0.android.result.Challenge
import com.auth0.android.result.Credentials
import com.auth0.android.result.DatabaseUser
import com.auth0.android.result.PasskeyChallenge
import com.auth0.android.result.PasskeyRegistrationChallenge
import com.auth0.android.result.SSOCredentials
import com.auth0.android.result.UserProfile
import com.google.gson.Gson
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.IOException
import java.io.Reader
import java.security.PublicKey

/**
 * API client for Auth0 Authentication API.
 * ```
 * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
 * val client = AuthenticationAPIClient(auth0)
 * ```
 *
 * @see [Auth API docs](https://auth0.com/docs/auth-api)
 */
public class AuthenticationAPIClient @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE) internal constructor(
    private val auth0: Auth0,
    private val factory: RequestFactory<AuthenticationException>,
    private val gson: Gson
) : SenderConstraining<AuthenticationAPIClient> {

    private var dPoP: DPoP? = null

    /**
     * Creates a new API client instance providing Auth0 account info.
     *
     * Example usage:
     *
     * ```
     * val auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
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
     * Enable DPoP for this client.
     */
    public override fun useDPoP(context: Context): AuthenticationAPIClient {
        dPoP = DPoP(context)
        return this
    }

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
     * Sign-in a user using passkeys.
     * This should be called after the client has received the passkey challenge from the server and generated the public key response.
     * The default scope used is 'openid profile email'.
     *
     * Requires the client to have the **Passkey** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types)
     * to learn how to enable it.
     *
     * Example usage:
     *
     * ```
     * client.signinWithPasskey("{authSession}", "{authResponse}","{realm}","${organization}")
     *       .validateClaims() //mandatory
     *       .setScope("{scope}")
     *       .start(object: Callback<Credentials, AuthenticationException> {
     *           override fun onFailure(error: AuthenticationException) { }
     *           override fun onSuccess(result: Credentials) { }
     * })
     * ```
     *
     * @param authSession the auth session received from the server as part of the public key challenge request.
     * @param authResponse the [PublicKeyCredentials] authentication response
     * @param realm the connection to use. If excluded, the application will use the default connection configured in the tenant
     * @param organization id of the organization to be associated with the user while signing in
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun signinWithPasskey(
        authSession: String,
        authResponse: PublicKeyCredentials,
        realm: String? = null,
        organization: String? = null,
    ): AuthenticationRequest {
        val params = ParameterBuilder.newBuilder().apply {
            setGrantType(ParameterBuilder.GRANT_TYPE_PASSKEY)
            set(AUTH_SESSION_KEY, authSession)
            realm?.let { setRealm(it) }
            organization?.let { set(ORGANIZATION_KEY, organization) }
        }.asDictionary()

        return loginWithToken(params)
            .addParameter(
                AUTH_RESPONSE_KEY,
                Gson().toJsonTree(authResponse)
            ) as AuthenticationRequest
    }


    /**
     * Sign-in a user using passkeys.
     * This should be called after the client has received the passkey challenge from the server and generated the public key response.
     * The default scope used is 'openid profile email'.
     *
     * Requires the client to have the **Passkey** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types)
     * to learn how to enable it.
     *
     * Example usage:
     *
     * ```
     * client.signinWithPasskey("{authSession}", "{authResponse}","{realm}","{organization}")
     *       .validateClaims() //mandatory
     *       .setScope("{scope}")
     *       .start(object: Callback<Credentials, AuthenticationException> {
     *           override fun onFailure(error: AuthenticationException) { }
     *           override fun onSuccess(result: Credentials) { }
     * })
     * ```
     *
     * @param authSession the auth session received from the server as part of the public key challenge request.
     * @param authResponse the public key credential authentication response in JSON string format that follows the standard webauthn json format
     * @param realm the connection to use. If excluded, the application will use the default connection configured in the tenant
     * @param organization id of the organization to be associated with the user while signing in
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun signinWithPasskey(
        authSession: String,
        authResponse: String,
        realm: String? = null,
        organization: String? = null,
    ): AuthenticationRequest {
        val publicKeyCredentials = gson.fromJson(
            authResponse,
            PublicKeyCredentials::class.java
        )
        return signinWithPasskey(authSession, publicKeyCredentials, realm, organization)
    }


    /**
     *  Sign-up a user and returns a challenge for private and public key generation.
     *  The default scope used is 'openid profile email'.
     *  Requires the client to have the **Passkey** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types)
     *  to learn how to enable it.
     *
     * Example usage:
     *
     *
     * ```
     * client.signupWithPasskey("{userData}","{realm}","{organization}")
     *      .addParameter("scope","scope")
     *      .start(object: Callback<PasskeyRegistration, AuthenticationException> {
     *          override fun onSuccess(result: PasskeyRegistration) { }
     *          override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     *  @param userData user information of the client
     *  @param realm the connection to use. If excluded, the application will use the default connection configured in the tenant
     *  @param organization id of the organization to be associated with the user while signing up
     *  @return  a request to configure and start that will yield [PasskeyRegistrationChallenge]
     */
    public fun signupWithPasskey(
        userData: UserData,
        realm: String? = null,
        organization: String? = null
    ): Request<PasskeyRegistrationChallenge, AuthenticationException> {
        val user = gson.toJsonTree(userData)
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(PASSKEY_PATH)
            .addPathSegment(REGISTER_PATH)
            .build()

        val params = ParameterBuilder.newBuilder().apply {
            setClientId(clientId)
            realm?.let { setRealm(it) }
            organization?.let { set(ORGANIZATION_KEY, it) }
        }.asDictionary()

        val passkeyRegistrationChallengeAdapter: JsonAdapter<PasskeyRegistrationChallenge> =
            GsonAdapter(
                PasskeyRegistrationChallenge::class.java, gson
            )
        val post = factory.post(url.toString(), passkeyRegistrationChallengeAdapter)
            .addParameters(params) as BaseRequest<PasskeyRegistrationChallenge, AuthenticationException>
        post.addParameter(USER_PROFILE_KEY, user)
        return post
    }


    /**
     * Request for a challenge to initiate passkey login flow
     * Requires the client to have the **Passkey** Grant Type enabled. See [Client Grant Types](https://auth0.com/docs/clients/client-grant-types)
     * to learn how to enable it.
     *
     * Example usage:
     *
     * ```
     * client.passkeyChallenge("{realm}", "{organization}")
     *    .start(object: Callback<PasskeyChallenge, AuthenticationException> {
     *        override fun onSuccess(result: PasskeyChallenge) { }
     *        override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param realm the connection to use. If excluded, the application will use the default connection configured in the tenant
     * @param organization id of the organization to be associated with the user while signing in
     * @return a request to configure and start that will yield [PasskeyChallenge]
     */
    public fun passkeyChallenge(
        realm: String? = null,
        organization: String? = null
    ): Request<PasskeyChallenge, AuthenticationException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(PASSKEY_PATH)
            .addPathSegment(CHALLENGE_PATH)
            .build()

        val parameters = ParameterBuilder.newBuilder().apply {
            setClientId(clientId)
            realm?.let { setRealm(it) }
            organization?.let { set(ORGANIZATION_KEY, organization) }
        }.asDictionary()

        val passkeyChallengeAdapter: JsonAdapter<PasskeyChallenge> = GsonAdapter(
            PasskeyChallenge::class.java, gson
        )

        return factory.post(url.toString(), passkeyChallengeAdapter)
            .addParameters(parameters)
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
        return tokenExchange(tokenType, token)
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
     * @param tokenType type of the token from  [Credentials]. Defaults to Bearer.
     * @return a request to start
     */
    public fun userInfo(
        accessToken: String, tokenType: String = "Bearer"
    ): Request<UserProfile, AuthenticationException> {
        return profileRequest()
            .addHeader(HEADER_AUTHORIZATION, "$tokenType $accessToken")
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
     * The Custom Token Exchange feature allows clients to exchange their existing tokens for Auth0 tokens by calling the `/oauth/token` endpoint with specific parameters.
     * The default scope used is 'openid profile email'.
     *
     * Example usage:
     *
     * ```
     * client.customTokenExchange("{subject token type}", "{subject token}")
     *       .validateClaims() //mandatory
     *       .setScope("{scope}")
     *       .setAudience("{audience}")
     *       .start(object: Callback<Credentials, AuthenticationException> {
     *       override fun onSuccess(result: Credentials) { }
     *       override fun onFailure(error: AuthenticationException) { }
     *  })
     *  ```
     *
     * @param subjectTokenType the subject token type that is associated with the existing Identity Provider. e.g. 'http://acme.com/legacy-token'
     * @param subjectToken   the subject token, typically obtained through the Identity Provider's SDK
     * @param organization  id of the organization the user belongs to
     * @return a request to configure and start that will yield [Credentials]
     */
    public fun customTokenExchange(
        subjectTokenType: String,
        subjectToken: String,
        organization: String? = null
    ): AuthenticationRequest {
        return tokenExchange(subjectTokenType, subjectToken, organization)
    }

    /**
     * Requests new Credentials using a valid Refresh Token. You can request credentials for a specific API by passing its audience value. The default scopes
     * configured for the API will be granted if you don't request any specific scopes.
     *
     *
     * This method will use the /oauth/token endpoint with the 'refresh_token' grant, and the response will include an id_token and an access_token if 'openid' scope was requested when the refresh_token was obtained.
     * Additionally, if the application has Refresh Token Rotation configured, a new one-time use refresh token will also be included in the response.
     *
     * The scope of the newly received Access Token can be reduced sending the scope parameter with this request.
     *
     * Example usage:
     * ```
     * client.renewAuth("{refresh_token}","{audience}","{scope})
     *     .start(object: Callback<Credentials, AuthenticationException> {
     *         override fun onSuccess(result: Credentials) { }
     *         override fun onFailure(error: AuthenticationException) { }
     * })
     * ```
     *
     * @param refreshToken used to fetch the new Credentials.
     * @param audience Identifier of the API that your application is requesting access to. Defaults to null.
     * @param scope Space-separated list of scope values to request. Defaults to null.
     * @return a request to start
     */
    public fun renewAuth(
        refreshToken: String,
        audience: String? = null,
        scope: String? = null
    ): Request<Credentials, AuthenticationException> {
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setRefreshToken(refreshToken)
            .setGrantType(ParameterBuilder.GRANT_TYPE_REFRESH_TOKEN)
            .apply {
                audience?.let {
                    setAudience(it)
                }
                scope?.let {
                    setScope(it)
                }
            }
            .asDictionary()
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val credentialsAdapter = GsonAdapter(
            Credentials::class.java, gson
        )
        val request = factory.post(url.toString(), credentialsAdapter, dPoP)
            .addParameters(parameters)
        return request
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
        val parameters = ParameterBuilder.newBuilder()
            .setClientId(clientId)
            .setGrantType(ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE)
            .set(OAUTH_CODE_KEY, authorizationCode).set(REDIRECT_URI_KEY, redirectUri)
            .set("code_verifier", codeVerifier)
            .asDictionary()
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val credentialsAdapter: JsonAdapter<Credentials> = GsonAdapter(
            Credentials::class.java, gson
        )
        val request = factory.post(url.toString(), credentialsAdapter, dPoP)
            .addParameters(parameters)
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
     * Creates a new request to exchange a refresh token for a session transfer token that can be used to perform web single sign-on.
     *
     * When opening your website on any browser or web view, add the session transfer token to the URL as a query
     * parameter. Then your website can redirect the user to Auth0's `/authorize` endpoint, passing along the query
     * parameter with the session transfer token. For example,
     * `https://example.com/login?session_transfer_token=THE_TOKEN`.
     *
     * ##Availability
     *
     * This feature is currently available in
     * [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access).
     * Please reach out to Auth0 support to get it enabled for your tenant.
     *
     *
     * @param refreshToken A valid refresh token obtained as part of Auth0 authentication
     * @return a request to fetch a session transfer token
     *
     */
    public fun ssoExchange(refreshToken: String): Request<SSOCredentials, AuthenticationException> {
        val params = ParameterBuilder.newBuilder()
            .setGrantType(ParameterBuilder.REFRESH_TOKEN_KEY)
            .setAudience("urn:${auth0.domain}:session_transfer")
            .set(ParameterBuilder.REFRESH_TOKEN_KEY, refreshToken)
            .asDictionary()
        return loginWithTokenGeneric<SSOCredentials>(params)
    }

    /**
     * Helper function to make a request to the /oauth/token endpoint with a custom response type.
     */
    private inline fun <reified T> loginWithTokenGeneric(parameters: Map<String, String>): Request<T, AuthenticationException> {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val requestParameters =
            ParameterBuilder.newBuilder()
                .setClientId(clientId)
                .addAll(parameters)
                .asDictionary()
        val adapter: JsonAdapter<T> = GsonAdapter(
            T::class.java, gson
        )
        val request = factory.post(url.toString(), adapter, dPoP)
            .addParameters(requestParameters)
        return request
    }

    /**
     * Helper function to make a request to the /oauth/token endpoint.
     */
    private fun loginWithToken(parameters: Map<String, String>): AuthenticationRequest {
        val url = auth0.getDomainUrl().toHttpUrl().newBuilder()
            .addPathSegment(OAUTH_PATH)
            .addPathSegment(TOKEN_PATH)
            .build()
        val requestParameters =
            ParameterBuilder.newBuilder()
                .setClientId(clientId)
                .addAll(parameters)
                .asDictionary()
        val credentialsAdapter: JsonAdapter<Credentials> = GsonAdapter(
            Credentials::class.java, gson
        )
        val request = BaseAuthenticationRequest(
            factory.post(url.toString(), credentialsAdapter, dPoP), clientId, baseURL
        )
        request.addParameters(requestParameters)
        return request
    }

    /**
     * Helper function to make a request to the /oauth/token endpoint with the token exchange grant type.
     */
    private fun tokenExchange(
        subjectTokenType: String,
        subjectToken: String,
        organization: String? = null
    ): AuthenticationRequest {
        val parameters = ParameterBuilder.newAuthenticationBuilder().apply {
            setGrantType(ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE)
            set(SUBJECT_TOKEN_TYPE_KEY, subjectTokenType)
            set(SUBJECT_TOKEN_KEY, subjectToken)
            organization?.let {
                set(ORGANIZATION_KEY, it)
            }
        }.asDictionary()
        return loginWithToken(parameters)
    }

    private fun profileRequest(): Request<UserProfile, AuthenticationException> {
        val url =
            auth0.getDomainUrl().toHttpUrl().newBuilder()
                .addPathSegment(USER_INFO_PATH)
                .build()
        val userProfileAdapter: JsonAdapter<UserProfile> = GsonAdapter(
            UserProfile::class.java, gson
        )
        return factory.get(url.toString(), userProfileAdapter, dPoP)
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
        private const val ORGANIZATION_KEY = "organization"
        private const val USER_METADATA_KEY = "user_metadata"
        private const val AUTH_SESSION_KEY = "auth_session"
        private const val AUTH_RESPONSE_KEY = "authn_response"
        private const val USER_PROFILE_KEY = "user_profile"
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
        private const val PASSKEY_PATH = "passkey"
        private const val REGISTER_PATH = "register"
        private const val HEADER_AUTHORIZATION = "Authorization"
        private const val WELL_KNOWN_PATH = ".well-known"
        private const val JWKS_FILE_PATH = "jwks.json"
        private const val TAG = "AuthenticationAPIClient"
        private fun createErrorAdapter(): ErrorAdapter<AuthenticationException> {
            val mapAdapter = forMap(GsonProvider.gson)
            return object : ErrorAdapter<AuthenticationException> {
                override fun fromRawResponse(
                    statusCode: Int, bodyText: String, headers: Map<String, List<String>>
                ): AuthenticationException {
                    return AuthenticationException(bodyText, statusCode)
                }

                @Throws(IOException::class)
                override fun fromJsonResponse(
                    statusCode: Int, reader: Reader
                ): AuthenticationException {
                    val values = mapAdapter.fromJson(reader)
                    return AuthenticationException(values, statusCode)
                }

                override fun fromException(cause: Throwable): AuthenticationException {
                    if (isNetworkError(cause)) {
                        return AuthenticationException(
                            "Failed to execute the network request", NetworkErrorException(cause)
                        )
                    }
                    if (cause is DPoPException) {
                        return AuthenticationException(
                            cause.message ?: "Error while attaching DPoP proof", cause
                        )
                    }
                    return AuthenticationException(
                        "Something went wrong", Auth0Exception("Something went wrong", cause)
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