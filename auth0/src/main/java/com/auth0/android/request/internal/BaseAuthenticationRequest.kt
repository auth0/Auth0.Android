package com.auth0.android.request.internal;

import androidx.annotation.NonNull;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.request.Request;
import com.auth0.android.result.Credentials;

import java.util.Map;

import static com.auth0.android.authentication.ParameterBuilder.AUDIENCE_KEY;
import static com.auth0.android.authentication.ParameterBuilder.CONNECTION_KEY;
import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_KEY;
import static com.auth0.android.authentication.ParameterBuilder.REALM_KEY;
import static com.auth0.android.authentication.ParameterBuilder.SCOPE_KEY;

public class BaseAuthenticationRequest implements AuthenticationRequest {

    private final Request<Credentials, AuthenticationException> request;

    public BaseAuthenticationRequest(@NonNull Request<Credentials, AuthenticationException> request) {
        this.request = request;
    }

    /**
     * Sets the 'grant_type' parameter
     *
     * @param grantType grant type
     * @return itself
     */
    @NonNull
    @Override
    public AuthenticationRequest setGrantType(@NonNull String grantType) {
        addParameter(GRANT_TYPE_KEY, grantType);
        return this;
    }

    /**
     * Sets the 'connection' parameter.
     *
     * @param connection name of the connection
     * @return itself
     */
    @NonNull
    @Override
    public AuthenticationRequest setConnection(@NonNull String connection) {
        addParameter(CONNECTION_KEY, connection);
        return this;
    }

    /**
     * Sets the 'realm' parameter. A realm identifies the host against which the authentication will be made, and usually helps to know which username and password to use.
     *
     * @param realm name of the realm
     * @return itself
     */
    @NonNull
    @Override
    public AuthenticationRequest setRealm(@NonNull String realm) {
        addParameter(REALM_KEY, realm);
        return this;
    }

    /**
     * Sets the 'scope' parameter.
     *
     * @param scope a scope value
     * @return itself
     */
    @NonNull
    @Override
    public AuthenticationRequest setScope(@NonNull String scope) {
        addParameter(SCOPE_KEY, scope);
        return this;
    }

    /**
     * Sets the 'audience' parameter.
     *
     * @param audience an audience value
     * @return itself
     */
    @NonNull
    @Override
    public AuthenticationRequest setAudience(@NonNull String audience) {
        addParameter(AUDIENCE_KEY, audience);
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest addParameters(@NonNull Map<String, String> parameters) {
        request.addParameters(parameters);
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest addParameter(@NonNull String name, @NonNull String value) {
        request.addParameter(name, value);
        return this;
    }

    @NonNull
    @Override
    public AuthenticationRequest addHeader(@NonNull String name, @NonNull String value) {
        request.addHeader(name, value);
        return this;
    }

    @Override
    public void start(@NonNull BaseCallback<Credentials, AuthenticationException> callback) {
        request.start(callback);
    }

    @NonNull
    @Override
    public Credentials execute() throws Auth0Exception {
        return request.execute();
    }
}
