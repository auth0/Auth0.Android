package com.auth0.android.request;

import androidx.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;

/**
 * Request to authenticate a user with Auth0 Authentication API
 */
public interface AuthenticationRequest extends Request<Credentials, AuthenticationException> {

    /**
     * Sets the 'grant_type' parameter
     *
     * @param grantType grant type
     * @return itself
     */
    @NonNull
    AuthenticationRequest setGrantType(@NonNull String grantType);

    /**
     * Sets the 'connection' parameter
     *
     * @param connection name of the connection
     * @return itself
     */
    @NonNull
    AuthenticationRequest setConnection(@NonNull String connection);

    /**
     * Sets the 'realm' parameter. A realm identifies the host against which the authentication will be made, and usually helps to know which username and password to use.
     *
     * @param realm name of the realm to use.
     * @return itself
     */
    @NonNull
    AuthenticationRequest setRealm(@NonNull String realm);

    /**
     * Sets the 'scope' parameter.
     *
     * @param scope a scope value
     * @return itself
     */
    @NonNull
    AuthenticationRequest setScope(@NonNull String scope);

    /**
     * Sets the 'audience' parameter.
     *
     * @param audience an audience value
     * @return itself
     */
    @NonNull
    AuthenticationRequest setAudience(@NonNull String audience);

}
