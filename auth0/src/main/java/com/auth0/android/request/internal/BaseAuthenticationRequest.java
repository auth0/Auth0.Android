package com.auth0.android.request.internal;

import android.util.Log;

import androidx.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.request.AuthenticationRequest;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.util.HashMap;
import java.util.Map;

import static com.auth0.android.authentication.ParameterBuilder.AUDIENCE_KEY;
import static com.auth0.android.authentication.ParameterBuilder.CONNECTION_KEY;
import static com.auth0.android.authentication.ParameterBuilder.DEVICE_KEY;
import static com.auth0.android.authentication.ParameterBuilder.GRANT_TYPE_KEY;
import static com.auth0.android.authentication.ParameterBuilder.REALM_KEY;
import static com.auth0.android.authentication.ParameterBuilder.SCOPE_KEY;

class BaseAuthenticationRequest extends SimpleRequest<Credentials, AuthenticationException> implements AuthenticationRequest {

    private static final String TAG = BaseAuthenticationRequest.class.getSimpleName();

    public BaseAuthenticationRequest(HttpUrl url, OkHttpClient client, Gson gson, String httpMethod) {
        super(url, client, gson, httpMethod, Credentials.class, new AuthenticationErrorBuilder());
    }

    private boolean hasLegacyPath() {
        return !url.encodedPath().equals("/oauth/token");
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
        if (!hasLegacyPath()) {
            Log.w(TAG, "Not setting the 'connection' parameter as the request is using a OAuth 2.0 API Authorization endpoint that doesn't support it.");
            return this;
        }
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
        if (hasLegacyPath()) {
            Log.w(TAG, "Not setting the 'realm' parameter as the request is using a Legacy Authorization API endpoint that doesn't support it.");
            return this;
        }
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
    public AuthenticationRequest setScope(@NonNull String scope) {
        addParameter(SCOPE_KEY, scope);
        return this;
    }

    /**
     * Sets the 'device' parameter
     *
     * @param device a device name
     * @return itself
     */
    @NonNull
    public AuthenticationRequest setDevice(@NonNull String device) {
        addParameter(DEVICE_KEY, device);
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
    public AuthenticationRequest addAuthenticationParameters(@NonNull Map<String, Object> parameters) {
        final HashMap<String, Object> params = new HashMap<>(parameters);
        if (parameters.containsKey(CONNECTION_KEY)) {
            setConnection((String) params.remove(CONNECTION_KEY));
        }
        if (parameters.containsKey(REALM_KEY)) {
            setRealm((String) params.remove(REALM_KEY));
        }
        addParameters(params);
        return this;
    }

    @NonNull
    @Override
    public BaseAuthenticationRequest addHeader(@NonNull String name, @NonNull String value) {
        super.addHeader(name, value);
        return this;
    }
}
