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

package com.auth0.android.authentication;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;

import com.auth0.android.Auth0;
import com.auth0.android.authentication.request.DatabaseConnectionRequest;
import com.auth0.android.authentication.request.DelegationRequest;
import com.auth0.android.authentication.request.ProfileRequest;
import com.auth0.android.authentication.request.SignUpRequest;
import com.auth0.android.authentication.request.TokenRequest;
import com.auth0.android.request.AuthRequest;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.request.internal.AuthenticationErrorBuilder;
import com.auth0.android.request.internal.GsonProvider;
import com.auth0.android.request.internal.OkHttpClientFactory;
import com.auth0.android.request.internal.RequestFactory;
import com.auth0.android.result.Credentials;
import com.auth0.android.result.DatabaseUser;
import com.auth0.android.result.Delegation;
import com.auth0.android.result.UserProfile;
import com.auth0.android.util.Telemetry;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.security.PublicKey;
import java.util.Map;

import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_AUTHORIZATION_CODE;
import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_MFA_OTP;
import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_PASSWORD;
import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_PASSWORDLESS_OTP;
import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_PASSWORD_REALM;
import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_TOKEN_EXCHANGE;
import static com.auth0.android.authentication.ParameterBuilder.ID_TOKEN_KEY;
import static com.auth0.android.authentication.ParameterBuilder.SCOPE_OPENID;

/**
 * API client for Auth0 Authentication API.
 * <pre>
 * {@code
 * Auth0 auth0 = new Auth0("your_client_id", "your_domain");
 * AuthenticationAPIClient client = new AuthenticationAPIClient(auth0);
 * }
 * </pre>
 *
 * @see <a href="https://auth0.com/docs/auth-api">Auth API docs</a>
 */
public class AuthenticationAPIClient {

    private static final String SMS_CONNECTION = "sms";
    private static final String EMAIL_CONNECTION = "email";
    private static final String USERNAME_KEY = "username";
    private static final String PASSWORD_KEY = "password";
    private static final String EMAIL_KEY = "email";
    private static final String PHONE_NUMBER_KEY = "phone_number";
    private static final String OAUTH_CODE_KEY = "code";
    private static final String REDIRECT_URI_KEY = "redirect_uri";
    private static final String TOKEN_KEY = "token";
    private static final String MFA_TOKEN_KEY = "mfa_token";
    private static final String ONE_TIME_PASSWORD_KEY = "otp";
    private static final String SUBJECT_TOKEN_KEY = "subject_token";
    private static final String SUBJECT_TOKEN_TYPE_KEY = "subject_token_type";
    private static final String DELEGATION_PATH = "delegation";
    private static final String ACCESS_TOKEN_PATH = "access_token";
    private static final String SIGN_UP_PATH = "signup";
    private static final String DB_CONNECTIONS_PATH = "dbconnections";
    private static final String CHANGE_PASSWORD_PATH = "change_password";
    private static final String PASSWORDLESS_PATH = "passwordless";
    private static final String START_PATH = "start";
    private static final String OAUTH_PATH = "oauth";
    private static final String TOKEN_PATH = "token";
    private static final String RESOURCE_OWNER_PATH = "ro";
    private static final String TOKEN_INFO_PATH = "tokeninfo";
    private static final String USER_INFO_PATH = "userinfo";
    private static final String REVOKE_PATH = "revoke";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String WELL_KNOWN_PATH = ".well-known";
    private static final String JWKS_FILE_PATH = "jwks.json";

    private final Auth0 auth0;
    private final OkHttpClient client;
    private final Gson gson;
    private final RequestFactory factory;
    private final ErrorBuilder<AuthenticationException> authErrorBuilder;


    /**
     * Creates a new API client instance providing Auth0 account info.
     *
     * @param auth0 account information
     */
    public AuthenticationAPIClient(@NonNull Auth0 auth0) {
        this(auth0, new RequestFactory(), new OkHttpClientFactory(), GsonProvider.buildGson());
    }

    /**
     * Creates a new API client instance using the 'com_auth0_client_id' and 'com_auth0_domain' values
     * defined in the project String resources file.
     *
     * @param context a valid Context
     */
    public AuthenticationAPIClient(@NonNull Context context) {
        this(new Auth0(context));
    }

    @VisibleForTesting
    AuthenticationAPIClient(Auth0 auth0, RequestFactory factory, OkHttpClientFactory clientFactory) {
        this(auth0, factory, clientFactory, GsonProvider.buildGson());
    }

    private AuthenticationAPIClient(Auth0 auth0, RequestFactory factory, OkHttpClientFactory clientFactory, Gson gson) {
        this.auth0 = auth0;
        this.client = clientFactory.createClient(auth0.isLoggingEnabled(),
                auth0.isTLS12Enforced(),
                auth0.getConnectTimeoutInSeconds(),
                auth0.getReadTimeoutInSeconds(),
                auth0.getWriteTimeoutInSeconds());
        this.gson = gson;
        this.factory = factory;
        this.authErrorBuilder = new AuthenticationErrorBuilder();
        final Telemetry telemetry = auth0.getTelemetry();
        if (telemetry != null) {
            factory.setClientInfo(telemetry.getValue());
        }
    }

    @NonNull
    public String getClientId() {
        return auth0.getClientId();
    }

    @NonNull
    public String getBaseURL() {
        return auth0.getDomainUrl();
    }

    /**
     * Set the value of 'User-Agent' header for every request to Auth0 Authentication API
     *
     * @param userAgent value to send in every request to Auth0
     */
    @SuppressWarnings("unused")
    public void setUserAgent(@NonNull String userAgent) {
        factory.setUserAgent(userAgent);
    }

    /**
     * Log in a user with email/username and password for a connection/realm.
     * In OIDC conformant mode ({@link Auth0#isOIDCConformant()}) it will use the password-realm grant type for the {@code /oauth/token} endpoint
     * otherwise it will use {@code /oauth/ro}, which requires your Application to have the <b>Resource Owner</b> Legacy Grant Type enabled. See <a href="https://auth0.com/docs/clients/client-grant-types">Client Grant Types</a> to learn how to enable it.
     * Example:
     * <pre>
     * {@code
     * client
     *      .login("{username or email}", "{password}", "{database connection name}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param usernameOrEmail   of the user depending of the type of DB connection
     * @param password          of the user
     * @param realmOrConnection realm to use in the authorize flow or the name of the database to authenticate with.
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest login(@NonNull String usernameOrEmail, @NonNull String password, @NonNull String realmOrConnection) {

        ParameterBuilder builder = ParameterBuilder.newBuilder()
                .set(USERNAME_KEY, usernameOrEmail)
                .set(PASSWORD_KEY, password);

        if (auth0.isOIDCConformant()) {
            final Map<String, Object> parameters = builder
                    .setGrantType(GRANT_TYPE_PASSWORD_REALM)
                    .setRealm(realmOrConnection)
                    .asDictionary();
            return loginWithToken(parameters);
        } else {
            final Map<String, Object> parameters = builder
                    .setGrantType(GRANT_TYPE_PASSWORD)
                    .setScope(SCOPE_OPENID)
                    .setConnection(realmOrConnection)
                    .asDictionary();
            return loginWithResourceOwner(parameters);
        }
    }

    /**
     * Log in a user with email/username and password using the password grant and the default directory
     * Example usage:
     * <pre>
     * {@code
     * client.login("{username or email}", "{password}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param usernameOrEmail of the user
     * @param password        of the user
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest login(@NonNull String usernameOrEmail, @NonNull String password) {
        Map<String, Object> requestParameters = ParameterBuilder.newBuilder()
                .set(USERNAME_KEY, usernameOrEmail)
                .set(PASSWORD_KEY, password)
                .setGrantType(GRANT_TYPE_PASSWORD)
                .asDictionary();

        return loginWithToken(requestParameters);
    }

    /**
     * Log in a user using the One Time Password code after they have received the 'mfa_required' error.
     * The MFA token tells the server the username or email, password and realm values sent on the first request.
     * Requires your client to have the <b>MFA</b> Grant Type enabled. See <a href="https://auth0.com/docs/clients/client-grant-types">Client Grant Types</a> to learn how to enable it.* Example usage:
     * <pre>
     * {@code
     * client.loginWithOTP("{mfa token}", "{one time password}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param mfaToken the token received in the previous {@link #login(String, String, String)} response.
     * @param otp      the one time password code provided by the resource owner, typically obtained from an
     *                 MFA application such as Google Authenticator or Guardian.
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest loginWithOTP(@NonNull String mfaToken, @NonNull String otp) {
        Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .setGrantType(GRANT_TYPE_MFA_OTP)
                .set(MFA_TOKEN_KEY, mfaToken)
                .set(ONE_TIME_PASSWORD_KEY, otp)
                .asDictionary();

        return loginWithToken(parameters);
    }

    /**
     * Log in a user with a OAuth 'access_token' of a Identity Provider like Facebook or Twitter using <a href="https://auth0.com/docs/api/authentication#social-with-provider-s-access-token">'\oauth\access_token' endpoint</a>
     * The default scope used is 'openid'.
     * Example usage:
     * <pre>
     * {@code
     * client.loginWithOAuthAccessToken("{token}", "{connection name}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param token      obtained from the IdP
     * @param connection that will be used to authenticate the user, e.g. 'facebook'
     * @return a request to configure and start that will yield {@link Credentials}
     * @deprecated The ability to exchange a third-party provider access token for Auth0 access tokens
     *             is part of the <a href="https://auth0.com/docs/api/authentication#social-with-provider-s-access-token">/oauth/access_token</a>
     *             Authentication API legacy endpoint, disabled as of June 2017. For selected social providers,
     *             there's support for a similar token exchange using the <a href="https://auth0.com/docs/api/authentication#token-exchange-for-native-social">Native Social token exchange</a>
     *             endpoint, using {@linkplain AuthenticationAPIClient#loginWithNativeSocialToken(String, String)}
     *             instead.
     */
    @NonNull
    @Deprecated
    public AuthRequest loginWithOAuthAccessToken(@NonNull String token, @NonNull String connection) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(ACCESS_TOKEN_PATH)
                .build();

        Map<String, Object> parameters = ParameterBuilder.newAuthenticationBuilder()
                .setClientId(getClientId())
                .setConnection(connection)
                .setAccessToken(token)
                .asDictionary();

        AuthRequest authRequest = factory.authenticationPOST(url, client, gson);
        authRequest.addAuthenticationParameters(parameters);
        return authRequest;
    }

    /**
     * Log in a user using a token obtained from a Native Social Identity Provider, such as Facebook, using <a href="https://auth0.com/docs/api/authentication#token-exchange-for-native-social">'\oauth\token' endpoint</a>
     * The default scope used is 'openid'.
     * Example usage:
     * <pre>
     * {@code
     * client.loginWithNativeSocialToken("{subject token}", "{subject token type}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param token     the subject token, typically obtained through the Identity Provider's SDK
     * @param tokenType the subject token type that is associated with this Identity Provider. e.g. 'http://auth0.com/oauth/token-type/facebook-session-access-token'
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest loginWithNativeSocialToken(@NonNull String token, @NonNull String tokenType) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(TOKEN_PATH)
                .build();

        Map<String, Object> parameters = ParameterBuilder.newAuthenticationBuilder()
                .setGrantType(GRANT_TYPE_TOKEN_EXCHANGE)
                .setClientId(getClientId())
                .set(SUBJECT_TOKEN_KEY, token)
                .set(SUBJECT_TOKEN_TYPE_KEY, tokenType)
                .asDictionary();

        AuthRequest authRequest = factory.authenticationPOST(url, client, gson);
        authRequest.addAuthenticationParameters(parameters);
        return authRequest;
    }

    /**
     * Log in a user using a phone number and a verification code received via SMS (Part of passwordless login flow)
     * The default scope used is 'openid'.
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * Example usage:
     * <pre>
     * {@code
     * client.loginWithPhoneNumber("{phone number}", "{code}", "{passwordless connection name}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param phoneNumber       where the user received the verification code
     * @param verificationCode  sent by Auth0 via SMS
     * @param realmOrConnection to end the passwordless authentication on
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest loginWithPhoneNumber(@NonNull String phoneNumber, @NonNull String verificationCode, @NonNull String realmOrConnection) {
        ParameterBuilder builder = ParameterBuilder.newAuthenticationBuilder()
                .setClientId(getClientId())
                .set(USERNAME_KEY, phoneNumber);

        if (auth0.isOIDCConformant()) {
            Map<String, Object> parameters = builder
                    .setGrantType(GRANT_TYPE_PASSWORDLESS_OTP)
                    .set(ONE_TIME_PASSWORD_KEY, verificationCode)
                    .setRealm(realmOrConnection)
                    .asDictionary();
            return loginWithToken(parameters);
        } else {
            Map<String, Object> parameters = builder
                    .setGrantType(GRANT_TYPE_PASSWORD)
                    .set(PASSWORD_KEY, verificationCode)
                    .setConnection(realmOrConnection)
                    .asDictionary();
            return loginWithResourceOwner(parameters);
        }
    }

    /**
     * Log in a user using a phone number and a verification code received via SMS (Part of passwordless login flow).
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * By default it will try to authenticate using the "sms" connection.
     * Example usage:
     * <pre>
     * {@code
     * client.loginWithPhoneNumber("{phone number}", "{code}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param phoneNumber      where the user received the verification code
     * @param verificationCode sent by Auth0 via SMS
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest loginWithPhoneNumber(@NonNull String phoneNumber, @NonNull String verificationCode) {
        return loginWithPhoneNumber(phoneNumber, verificationCode, SMS_CONNECTION);
    }

    /**
     * Log in a user using an email and a verification code received via Email (Part of passwordless login flow).
     * The default scope used is 'openid'.
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * Example usage:
     * <pre>
     * {@code
     * client.loginWithEmail("{email}", "{code}", "{passwordless connection name}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param email             where the user received the verification code
     * @param verificationCode  sent by Auth0 via Email
     * @param realmOrConnection to end the passwordless authentication on
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest loginWithEmail(@NonNull String email, @NonNull String verificationCode, @NonNull String realmOrConnection) {
        ParameterBuilder builder = ParameterBuilder.newAuthenticationBuilder()
                .setClientId(getClientId())
                .set(USERNAME_KEY, email);

        if (auth0.isOIDCConformant()) {
            Map<String, Object> parameters = builder
                    .setGrantType(GRANT_TYPE_PASSWORDLESS_OTP)
                    .set(ONE_TIME_PASSWORD_KEY, verificationCode)
                    .setRealm(realmOrConnection)
                    .asDictionary();
            return loginWithToken(parameters);
        } else {
            Map<String, Object> parameters = builder
                    .setGrantType(GRANT_TYPE_PASSWORD)
                    .set(PASSWORD_KEY, verificationCode)
                    .setConnection(realmOrConnection)
                    .asDictionary();
            return loginWithResourceOwner(parameters);
        }
    }

    /**
     * Log in a user using an email and a verification code received via Email (Part of passwordless login flow)
     * By default it will try to authenticate using the "email" connection.
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * Example usage:
     * <pre>
     * {@code
     * client.loginWithEmail("{email}", "{code}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param email            where the user received the verification code
     * @param verificationCode sent by Auth0 via Email
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public AuthRequest loginWithEmail(@NonNull String email, @NonNull String verificationCode) {
        return loginWithEmail(email, verificationCode, EMAIL_CONNECTION);
    }

    /**
     * Returns the information of the user associated with the given access_token.
     * Example usage:
     * <pre>
     * {@code
     * client.userInfo("{access_token}")
     *      .start(new BaseCallback<UserProfile>() {
     *          {@literal}Override
     *          public void onSuccess(UserProfile payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param accessToken used to fetch it's information
     * @return a request to start
     */
    @NonNull
    public ParameterizableRequest<UserProfile, AuthenticationException> userInfo(@NonNull String accessToken) {
        return profileRequest()
                .addHeader(HEADER_AUTHORIZATION, "Bearer " + accessToken);
    }

    /**
     * Fetch the token information from Auth0.
     * Example usage:
     * <pre>
     * {@code
     * client.tokenInfo("{id_token}")
     *      .start(new BaseCallback<UserProfile>() {
     *          {@literal}Override
     *          public void onSuccess(UserProfile payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param idToken used to fetch it's information
     * @return a request to start
     * @deprecated Please use {@link AuthenticationAPIClient#userInfo(String)} instead.
     */
    @NonNull
    @Deprecated
    public ParameterizableRequest<UserProfile, AuthenticationException> tokenInfo(@NonNull String idToken) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(TOKEN_INFO_PATH)
                .build();

        return factory.POST(url, client, gson, UserProfile.class, authErrorBuilder)
                .addParameter(ID_TOKEN_KEY, idToken);
    }

    /**
     * Creates a user in a DB connection using <a href="https://auth0.com/docs/api/authentication#signup">'/dbconnections/signup' endpoint</a>
     * Example usage:
     * <pre>
     * {@code
     * client.createUser("{email}", "{password}", "{username}", "{database connection name}")
     *      .start(new BaseCallback<DatabaseUser>() {
     *          {@literal}Override
     *          public void onSuccess(DatabaseUser payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param username   of the user and must be non null
     * @param connection of the database to create the user on
     * @return a request to start
     */
    @NonNull
    public DatabaseConnectionRequest<DatabaseUser, AuthenticationException> createUser(@NonNull String email, @NonNull String password, @Nullable String username, @NonNull String connection) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(DB_CONNECTIONS_PATH)
                .addPathSegment(SIGN_UP_PATH)
                .build();

        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .set(USERNAME_KEY, username)
                .set(EMAIL_KEY, email)
                .set(PASSWORD_KEY, password)
                .setConnection(connection)
                .setClientId(getClientId())
                .asDictionary();

        final ParameterizableRequest<DatabaseUser, AuthenticationException> request = factory.POST(url, client, gson, DatabaseUser.class, authErrorBuilder)
                .addParameters(parameters);
        return new DatabaseConnectionRequest<>(request);
    }

    /**
     * Creates a user in a DB connection using <a href="https://auth0.com/docs/api/authentication#signup">'/dbconnections/signup' endpoint</a>
     * Example usage:
     * <pre>
     * {@code
     * client.createUser("{email}", "{password}", "{database connection name}")
     *      .start(new BaseCallback<DatabaseUser>() {
     *          {@literal}Override
     *          public void onSuccess(DatabaseUser payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param connection of the database to create the user on
     * @return a request to start
     */
    @NonNull
    public DatabaseConnectionRequest<DatabaseUser, AuthenticationException> createUser(@NonNull String email, @NonNull String password, @NonNull String connection) {
        return createUser(email, password, null, connection);
    }

    /**
     * Creates a user in a DB connection using <a href="https://auth0.com/docs/api/authentication#signup">'/dbconnections/signup' endpoint</a>
     * and then logs in the user. How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag.
     * Example usage:
     * <pre>
     * {@code
     * client.signUp("{email}", "{password}", "{username}", "{database connection name}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param username   of the user and must be non null
     * @param connection of the database to sign up with
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public SignUpRequest signUp(@NonNull String email, @NonNull String password, @NonNull String username, @NonNull String connection) {
        final DatabaseConnectionRequest<DatabaseUser, AuthenticationException> createUserRequest = createUser(email, password, username, connection);
        final AuthRequest authenticationRequest = login(email, password, connection);

        return new SignUpRequest(createUserRequest, authenticationRequest);
    }

    /**
     * Creates a user in a DB connection using <a href="https://auth0.com/docs/api/authentication#signup">'/dbconnections/signup' endpoint</a>
     * and then logs in the user. How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag.
     * Example usage:
     * <pre>
     * {@code
     * client.signUp("{email}", "{password}", "{database connection name}")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param email      of the user and must be non null
     * @param password   of the user and must be non null
     * @param connection of the database to sign up with
     * @return a request to configure and start that will yield {@link Credentials}
     */
    @NonNull
    public SignUpRequest signUp(@NonNull String email, @NonNull String password, @NonNull String connection) {
        final DatabaseConnectionRequest<DatabaseUser, AuthenticationException> createUserRequest = createUser(email, password, connection);
        final AuthRequest authenticationRequest = login(email, password, connection);
        return new SignUpRequest(createUserRequest, authenticationRequest);
    }

    /**
     * Request a reset password using <a href="https://auth0.com/docs/api/authentication#change-password">'/dbconnections/change_password'</a>
     * Example usage:
     * <pre>
     * {@code
     * client.resetPassword("{email}", "{database connection name}")
     *      .start(new BaseCallback<Void>() {
     *          {@literal}Override
     *          public void onSuccess(Void payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param email      of the user to request the password reset. An email will be sent with the reset instructions.
     * @param connection of the database to request the reset password on
     * @return a request to configure and start
     */
    @NonNull
    public DatabaseConnectionRequest<Void, AuthenticationException> resetPassword(@NonNull String email, @NonNull String connection) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(DB_CONNECTIONS_PATH)
                .addPathSegment(CHANGE_PASSWORD_PATH)
                .build();

        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .set(EMAIL_KEY, email)
                .setClientId(getClientId())
                .setConnection(connection)
                .asDictionary();

        final ParameterizableRequest<Void, AuthenticationException> request = factory.POST(url, client, gson, authErrorBuilder)
                .addParameters(parameters);
        return new DatabaseConnectionRequest<>(request);
    }

    /**
     * Request the revoke of a given refresh_token. Once revoked, the refresh_token cannot be used to obtain new tokens.
     * Your Auth0 Application Type should be set to 'Native' and Token Endpoint Authentication Method must be set to 'None'.
     * Example usage:
     * <pre>
     * {@code
     * client.revokeToken("{refresh_token}")
     *      .start(new BaseCallback<Void>() {
     *          {@literal}Override
     *          public void onSuccess(Void payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param refreshToken the token to revoke
     * @return a request to start
     *
     */
    @NonNull
    public ParameterizableRequest<Void, AuthenticationException> revokeToken(@NonNull String refreshToken) {
        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .set(TOKEN_KEY, refreshToken)
                .asDictionary();

        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(REVOKE_PATH)
                .build();

        return factory.POST(url, client, gson, authErrorBuilder)
                .addParameters(parameters);
    }

    /**
     * Requests new Credentials using a valid Refresh Token. The received token will have the same audience and scope as first requested. How the new Credentials are requested depends on the {@link Auth0#isOIDCConformant()} flag.
     * - If the instance is OIDC Conformant the endpoint will be /oauth/token with 'refresh_token' grant, and the response will include an id_token and an access_token if 'openid' scope was requested when the refresh_token was obtained.
     * In addition, if the application has Refresh Token Rotation configured, a new one-time use refresh token will also be included in the response.
     * - If the instance is not OIDC Conformant the endpoint will be /delegation with 'urn:ietf:params:oauth:grant-type:jwt-bearer' grant, and the response will include an id_token.
     * Example usage:
     * <pre>
     * {@code
     * client.renewAuth("{refresh_token}")
     *      .addParameter("scope", "openid profile email")
     *      .start(new BaseCallback<Credentials>() {
     *          {@literal}Override
     *          public void onSuccess(Credentials payload) { }
     *
     *          {@literal}@Override
     *          public void onFailure(AuthenticationException error) { }
     *      });
     * }
     * </pre>
     *
     * @param refreshToken used to fetch the new Credentials.
     * @return a request to start
     */
    @NonNull
    public ParameterizableRequest<Credentials, AuthenticationException> renewAuth(@NonNull String refreshToken) {
        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .setRefreshToken(refreshToken)
                .setGrantType(auth0.isOIDCConformant() ? ParameterBuilder.GRANT_TYPE_REFRESH_TOKEN : ParameterBuilder.GRANT_TYPE_JWT)
                .asDictionary();

        HttpUrl url;
        if (auth0.isOIDCConformant()) {
            url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                    .addPathSegment(OAUTH_PATH)
                    .addPathSegment(TOKEN_PATH)
                    .build();
        } else {
            url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                    .addPathSegment(DELEGATION_PATH)
                    .build();
        }

        return factory.POST(url, client, gson, Credentials.class, authErrorBuilder)
                .addParameters(parameters);
    }

    /**
     * Performs a <a href="https://auth0.com/docs/api/authentication#delegation">delegation</a> request that will yield a new Auth0 'id_token'
     * Example usage:
     * <pre>
     * {@code
     * client.delegationWithIdToken("{id token}")
     *      .start(new BaseCallback<Delegation>() {
     *          {@literal}Override
     *          public void onSuccess(Delegation payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param idToken issued by Auth0 for the user. The token must not be expired.
     * @return a request to configure and start
     * @deprecated The {@code /delegation} endpoint of the Auth0 Authorization API has been deprecated.
     *             This method will be removed in version 2 of this SDK.
     */
    @NonNull
    @Deprecated
    public DelegationRequest<Delegation> delegationWithIdToken(@NonNull String idToken) {
        ParameterizableRequest<Delegation, AuthenticationException> request = delegation(Delegation.class)
                .addParameter(ParameterBuilder.ID_TOKEN_KEY, idToken);

        return new DelegationRequest<>(request)
                .setApiType(DelegationRequest.DEFAULT_API_TYPE);
    }

    /**
     * Performs a <a href="https://auth0.com/docs/api/authentication#delegation">delegation</a> request that will yield a new Auth0 'id_token'.
     * Check our <a href="https://auth0.com/docs/refresh-token">refresh token</a> docs for more information
     * Example usage:
     * <pre>
     * {@code
     * client.delegationWithRefreshToken("{refresh token}")
     *      .start(new BaseCallback<Delegation>() {
     *          {@literal}Override
     *          public void onSuccess(Delegation payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param refreshToken issued by Auth0 for the user when using the 'offline_access' scope when logging in.
     * @return a request to configure and start
     * @deprecated The {@code /delegation} endpoint of the Auth0 Authorization API has been deprecated.
     *             This method will be removed in version 2 of this SDK.
     */
    @NonNull
    @Deprecated
    public DelegationRequest<Delegation> delegationWithRefreshToken(@NonNull String refreshToken) {
        ParameterizableRequest<Delegation, AuthenticationException> request = delegation(Delegation.class)
                .addParameter(ParameterBuilder.REFRESH_TOKEN_KEY, refreshToken);

        return new DelegationRequest<>(request)
                .setApiType(DelegationRequest.DEFAULT_API_TYPE);
    }

    /**
     * Performs a <a href="https://auth0.com/docs/api/authentication#delegation">delegation</a> request that will yield a delegation token.
     * Example usage:
     * <pre>
     * {@code
     * client.delegationWithIdToken("{id token}", "{app type, e.g. firebase}")
     *      .start(new BaseCallback<Map<String, Object>>() {
     *          {@literal}Override
     *          public void onSuccess(Map<String, Object> payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param idToken issued by Auth0 for the user. The token must not be expired.
     * @param apiType the delegation 'api_type' parameter
     * @return a request to configure and start
     * @deprecated The {@code /delegation} endpoint of the Auth0 Authorization API has been deprecated.
     *             This method will be removed in version 2 of this SDK.
     */
    @NonNull
    @Deprecated
    public DelegationRequest<Map<String, Object>> delegationWithIdToken(@NonNull String idToken, @NonNull String apiType) {
        ParameterizableRequest<Map<String, Object>, AuthenticationException> request = delegation()
                .addParameter(ParameterBuilder.ID_TOKEN_KEY, idToken);

        return new DelegationRequest<>(request)
                .setApiType(apiType);
    }

    /**
     * Start a passwordless flow with an <a href="https://auth0.com/docs/api/authentication#get-code-or-link">Email</a>.
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * Example usage:
     * <pre>
     * {@code
     * client.passwordlessWithEmail("{email}", PasswordlessType.CODE, "{passwordless connection name}")
     *      .start(new BaseCallback<Void>() {
     *          {@literal}Override
     *          public void onSuccess(Void payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param email            that will receive a verification code to use for login
     * @param passwordlessType indicate whether the email should contain a code, link or magic link (android {@literal &} iOS)
     * @param connection       the passwordless connection to start the flow with.
     * @return a request to configure and start
     */
    @NonNull
    public ParameterizableRequest<Void, AuthenticationException> passwordlessWithEmail(@NonNull String email, @NonNull PasswordlessType passwordlessType, @NonNull String connection) {
        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .set(EMAIL_KEY, email)
                .setSend(passwordlessType)
                .setConnection(connection)
                .asDictionary();

        return passwordless()
                .addParameters(parameters);
    }

    /**
     * Start a passwordless flow with an <a href="https://auth0.com/docs/api/authentication#get-code-or-link">Email</a>
     * By default it will try to authenticate using "email" connection.
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * Example usage:
     * <pre>
     * {@code
     * client.passwordlessWithEmail("{email}", PasswordlessType.CODE)
     *      .start(new BaseCallback<Void>() {
     *          {@literal}Override
     *          public void onSuccess(Void payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param email            that will receive a verification code to use for login
     * @param passwordlessType indicate whether the email should contain a code, link or magic link (android {@literal &} iOS)
     * @return a request to configure and start
     */
    @NonNull
    public ParameterizableRequest<Void, AuthenticationException> passwordlessWithEmail(@NonNull String email, @NonNull PasswordlessType passwordlessType) {
        return passwordlessWithEmail(email, passwordlessType, EMAIL_CONNECTION);
    }

    /**
     * Start a passwordless flow with a <a href="https://auth0.com/docs/api/authentication#get-code-or-link">SMS</a>
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * Example usage:
     * <pre>
     * {@code
     * client.passwordlessWithSms("{phone number}", PasswordlessType.CODE, "{passwordless connection name}")
     *      .start(new BaseCallback<Void>() {
     *          {@literal}Override
     *          public void onSuccess(Void payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param phoneNumber      where an SMS with a verification code will be sent
     * @param passwordlessType indicate whether the SMS should contain a code, link or magic link (android {@literal &} iOS)
     * @param connection       the passwordless connection to start the flow with.
     * @return a request to configure and start
     */
    @NonNull
    public ParameterizableRequest<Void, AuthenticationException> passwordlessWithSMS(@NonNull String phoneNumber, @NonNull PasswordlessType passwordlessType, @NonNull String connection) {
        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .set(PHONE_NUMBER_KEY, phoneNumber)
                .setSend(passwordlessType)
                .setConnection(connection)
                .asDictionary();
        return passwordless()
                .addParameters(parameters);
    }

    /**
     * Start a passwordless flow with a <a href="https://auth0.com/docs/api/authentication#get-code-or-link">SMS</a>
     * By default it will try to authenticate using the "sms" connection.
     * How the user is logged in depends on the {@link Auth0#isOIDCConformant()} flag. If this flag is set to true, your Application requires to have the <b>Passwordless OTP</b> Grant Type enabled.
     * If this flag is set to false, the <b>Resource Owner</b> Legacy Grant Type must be enabled instead.
     * See <a href="https://auth0.com/docs/clients/client-grant-types">Client Grant Types</a> to learn how to enable it.
     * Example usage:
     * <pre>
     * {@code
     * client.passwordlessWithSms("{phone number}", PasswordlessType.CODE)
     *      .start(new BaseCallback<Void>() {
     *          {@literal}Override
     *          public void onSuccess(Void payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @param phoneNumber      where an SMS with a verification code will be sent
     * @param passwordlessType indicate whether the SMS should contain a code, link or magic link (android {@literal &} iOS)
     * @return a request to configure and start
     */
    @NonNull
    public ParameterizableRequest<Void, AuthenticationException> passwordlessWithSMS(@NonNull String phoneNumber, @NonNull PasswordlessType passwordlessType) {
        return passwordlessWithSMS(phoneNumber, passwordlessType, SMS_CONNECTION);
    }

    /**
     * Performs a custom <a href="https://auth0.com/docs/api/authentication#delegation">delegation</a> request that will
     * yield a delegation token.
     * Example usage:
     * <pre>
     * {@code
     * client.delegation()
     *      .addParameter("api_type", "firebase")
     *      .start(new BaseCallback<Map<String, Object>>() {
     *          {@literal}Override
     *          public void onSuccess(Map<String, Object> payload) {}
     *
     *          {@literal}Override
     *          public void onFailure(AuthenticationException error) {}
     *      });
     * }
     * </pre>
     *
     * @return a request to configure and start
     * @deprecated The {@code /delegation} endpoint of the Auth0 Authorization API has been deprecated.
     *             This method will be removed in version 2 of this SDK.
     */
    @NonNull
    @Deprecated
    public ParameterizableRequest<Map<String, Object>, AuthenticationException> delegation() {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(DELEGATION_PATH)
                .build();

        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .setGrantType(ParameterBuilder.GRANT_TYPE_JWT)
                .asDictionary();

        return factory.rawPOST(url, client, gson, authErrorBuilder)
                .addParameters(parameters);
    }

    @SuppressWarnings("SameParameterValue")
    private <T> ParameterizableRequest<T, AuthenticationException> delegation(Class<T> clazz) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(DELEGATION_PATH)
                .build();

        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .setGrantType(ParameterBuilder.GRANT_TYPE_JWT)
                .asDictionary();

        return factory.POST(url, client, gson, clazz, authErrorBuilder)
                .addParameters(parameters);
    }

    /**
     * Start a custom passwordless flow
     *
     * @return a request to configure and start
     */
    private ParameterizableRequest<Void, AuthenticationException> passwordless() {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(PASSWORDLESS_PATH)
                .addPathSegment(START_PATH)
                .build();

        final Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .asDictionary();

        return factory.POST(url, client, gson, authErrorBuilder)
                .addParameters(parameters);
    }

    /**
     * Fetch the user's profile after it's authenticated by a login request.
     * If the login request fails, the returned request will fail
     *
     * @param authenticationRequest that will authenticate a user with Auth0 and return a {@link Credentials}
     * @return a {@link ProfileRequest} that first logins and the fetches the profile
     */
    @NonNull
    public ProfileRequest getProfileAfter(@NonNull AuthenticationRequest authenticationRequest) {
        final ParameterizableRequest<UserProfile, AuthenticationException> profileRequest = profileRequest();
        //noinspection deprecation
        return new ProfileRequest(authenticationRequest, profileRequest);
    }

    /**
     * Fetch the token information from Auth0, using the authorization_code grant type
     * For Public Client, e.g. Android apps ,you need to provide the code_verifier
     * used to generate the challenge sent to Auth0 {@literal /authorize} method like:
     * <pre>
     * {@code
     * AuthenticationAPIClient client = new AuthenticationAPIClient(new Auth0("clientId", "domain"));
     * client
     *     .token("code", "redirect_uri")
     *     .setCodeVerifier("code_verifier")
     *     .start(new Callback<Credentials> {...});
     * }
     * </pre>
     * For the rest of clients, clients who can safely keep a {@literal client_secret}, you need to provide it instead like:
     * <pre>
     * {@code
     * AuthenticationAPIClient client = new AuthenticationAPIClient(new Auth0("clientId", "domain"));
     * client
     *     .token("code", "redirect_uri")
     *     .start(new Callback<Credentials> {...});
     * }
     * </pre>
     *
     * @param authorizationCode the authorization code received from the /authorize call.
     * @param redirectUri       the uri sent to /authorize as the 'redirect_uri'.
     * @return a request to obtain access_token by exchanging a authorization code.
     */
    @NonNull
    public TokenRequest token(@NonNull String authorizationCode, @NonNull String redirectUri) {
        Map<String, Object> parameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .setGrantType(GRANT_TYPE_AUTHORIZATION_CODE)
                .set(OAUTH_CODE_KEY, authorizationCode)
                .set(REDIRECT_URI_KEY, redirectUri)
                .asDictionary();

        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(TOKEN_PATH)
                .build();

        ParameterizableRequest<Credentials, AuthenticationException> request = factory.POST(url, client, gson, Credentials.class, authErrorBuilder);
        request.addParameters(parameters);
        return new TokenRequest(request);
    }

    /**
     * Creates a new Request to obtain the JSON Web Keys associated with the Auth0 account under the given domain.
     * Only supports RSA keys used for signatures (Public Keys).
     *
     * @return a request to obtain the JSON Web Keys associated with this Auth0 account.
     */
    @NonNull
    public ParameterizableRequest<Map<String, PublicKey>, AuthenticationException> fetchJsonWebKeys() {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(WELL_KNOWN_PATH)
                .addPathSegment(JWKS_FILE_PATH)
                .build();
        TypeToken<Map<String, PublicKey>> jwksType = new TypeToken<Map<String, PublicKey>>() {
        };
        return factory.GET(url, client, gson, jwksType, authErrorBuilder);
    }

    private AuthRequest loginWithToken(Map<String, Object> parameters) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(TOKEN_PATH)
                .build();

        final Map<String, Object> requestParameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .addAll(parameters)
                .asDictionary();
        AuthRequest authRequest = factory.authenticationPOST(url, client, gson);
        authRequest.addAuthenticationParameters(requestParameters);
        return authRequest;
    }

    private AuthRequest loginWithResourceOwner(Map<String, Object> parameters) {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(OAUTH_PATH)
                .addPathSegment(RESOURCE_OWNER_PATH)
                .build();

        final Map<String, Object> requestParameters = ParameterBuilder.newBuilder()
                .setClientId(getClientId())
                .addAll(parameters)
                .asDictionary();
        AuthRequest authRequest = factory.authenticationPOST(url, client, gson);
        authRequest.addAuthenticationParameters(requestParameters);
        return authRequest;
    }

    private ParameterizableRequest<UserProfile, AuthenticationException> profileRequest() {
        HttpUrl url = HttpUrl.parse(auth0.getDomainUrl()).newBuilder()
                .addPathSegment(USER_INFO_PATH)
                .build();

        return factory.GET(url, client, gson, UserProfile.class, authErrorBuilder);
    }

}
