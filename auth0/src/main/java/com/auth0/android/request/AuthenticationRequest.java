package com.auth0.android.request;

import android.support.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Credentials;

import java.util.Map;

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
     * Sets the 'device' parameter
     *
     * @param device a device name
     * @return itself
     */
    @NonNull
    AuthenticationRequest setDevice(@NonNull String device);

    /**
     * Sets the 'audience' parameter.
     *
     * @param audience an audience value
     * @return itself
     */
    @NonNull
    AuthenticationRequest setAudience(@NonNull String audience);

    /**
     * Sets the 'access_token' parameter
     *
     * @param accessToken a access token
     * @return itself
     */
    @NonNull
    AuthenticationRequest setAccessToken(@NonNull String accessToken);

    /**
     * All all entries of the map as parameters of this request
     *
     * @param parameters to be added to the request
     * @return itself
     */
    @NonNull
    AuthenticationRequest addAuthenticationParameters(@NonNull Map<String, Object> parameters);

}
