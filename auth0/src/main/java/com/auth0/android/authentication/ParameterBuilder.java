/*
 * ParameterBuilder.java
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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.auth0.android.util.CheckHelper;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Builder for Auth0 Authentication API parameters
 * You can build your parameters like this
 * <pre>
 * {@code
 * Map<String, Object> parameters = ParameterBuilder.newBuilder()
 *      .setClientId("{CLIENT_ID}")
 *      .setConnection("{CONNECTION}")
 *      .set("{PARAMETER_NAME}", "{PARAMETER_VALUE}")
 *      .asDictionary();
 * }
 * </pre>
 *
 * @see ParameterBuilder#newBuilder()
 * @see ParameterBuilder#newAuthenticationBuilder()
 */
public class ParameterBuilder {

    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    public static final String GRANT_TYPE_PASSWORD = "password";
    public static final String GRANT_TYPE_PASSWORD_REALM = "http://auth0.com/oauth/grant-type/password-realm";
    public static final String GRANT_TYPE_JWT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    public static final String GRANT_TYPE_MFA_OTP = "http://auth0.com/oauth/grant-type/mfa-otp";
    public static final String GRANT_TYPE_PASSWORDLESS_OTP = "http://auth0.com/oauth/grant-type/passwordless/otp";
    public static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    public static final String SCOPE_OPENID = "openid";
    public static final String SCOPE_OFFLINE_ACCESS = "openid offline_access";

    public static final String ID_TOKEN_KEY = "id_token";
    public static final String SCOPE_KEY = "scope";
    public static final String REFRESH_TOKEN_KEY = "refresh_token";
    public static final String CONNECTION_KEY = "connection";
    public static final String REALM_KEY = "realm";
    public static final String ACCESS_TOKEN_KEY = "access_token";
    public static final String SEND_KEY = "send";
    public static final String CLIENT_ID_KEY = "client_id";
    public static final String GRANT_TYPE_KEY = "grant_type";
    public static final String DEVICE_KEY = "device";
    public static final String AUDIENCE_KEY = "audience";

    private final Map<String, Object> parameters;

    private ParameterBuilder(Map<String, Object> parameters) {
        CheckHelper.checkArgument(parameters != null, "Must provide non-null parameters");
        this.parameters = new HashMap<>(parameters);
    }

    /**
     * Sets the 'client_id' parameter
     *
     * @param clientId the application's client id
     * @return itself
     */
    @NonNull
    public ParameterBuilder setClientId(@NonNull String clientId) {
        return set(CLIENT_ID_KEY, clientId);
    }

    /**
     * Sets the 'grant_type' parameter
     *
     * @param grantType grant type
     * @return itself
     */
    @NonNull
    public ParameterBuilder setGrantType(@NonNull String grantType) {
        return set(GRANT_TYPE_KEY, grantType);
    }

    /**
     * Sets the 'connection' parameter
     *
     * @param connection name of the connection
     * @return itself
     */
    @NonNull
    public ParameterBuilder setConnection(@NonNull String connection) {
        return set(CONNECTION_KEY, connection);
    }

    /**
     * Sets the 'realm' parameter. A realm identifies the host against which the authentication will be made, and usually helps to know which username and password to use.
     *
     * @param realm name of the realm
     * @return itself
     */
    @NonNull
    public ParameterBuilder setRealm(@NonNull String realm) {
        return set(REALM_KEY, realm);
    }

    /**
     * Sets the 'scope' parameter.
     *
     * @param scope a scope value
     * @return itself
     */
    @NonNull
    public ParameterBuilder setScope(@NonNull String scope) {
        return set(SCOPE_KEY, scope);
    }

    /**
     * Sets the 'audience' parameter.
     *
     * @param audience an audience value
     * @return itself
     */
    @NonNull
    public ParameterBuilder setAudience(@NonNull String audience) {
        return set(AUDIENCE_KEY, audience);
    }

    /**
     * Sets the 'device' parameter
     *
     * @param device a device name
     * @return itself
     */
    @NonNull
    public ParameterBuilder setDevice(@NonNull String device) {
        return set(DEVICE_KEY, device);
    }

    /**
     * Sets the 'access_token' parameter
     *
     * @param accessToken a access token
     * @return itself
     */
    @NonNull
    public ParameterBuilder setAccessToken(@NonNull String accessToken) {
        return set(ACCESS_TOKEN_KEY, accessToken);
    }

    /**
     * Sets the 'refresh_token' parameter
     *
     * @param refreshToken a access token
     * @return itself
     */
    @NonNull
    public ParameterBuilder setRefreshToken(@NonNull String refreshToken) {
        return set(REFRESH_TOKEN_KEY, refreshToken);
    }

    /**
     * Sets the 'send' parameter
     *
     * @param passwordlessType the type of passwordless login
     * @return itself
     */
    @NonNull
    public ParameterBuilder setSend(@NonNull PasswordlessType passwordlessType) {
        return set(SEND_KEY, passwordlessType.getValue());
    }

    /**
     * Sets a parameter
     *
     * @param key   parameter name
     * @param value parameter value. A null value will remove the key if present.
     * @return itself
     */
    @NonNull
    public ParameterBuilder set(@NonNull String key, @Nullable Object value) {
        if (value == null) {
            this.parameters.remove(key);
        } else {
            this.parameters.put(key, value);
        }
        return this;
    }

    /**
     * Adds all parameter from a map
     *
     * @param parameters map with parameters to add. Null values will be skipped.
     * @return itself
     */
    @NonNull
    public ParameterBuilder addAll(@Nullable Map<String, Object> parameters) {
        if (parameters != null) {
            for (String k : parameters.keySet()) {
                if (parameters.get(k) != null) {
                    this.parameters.put(k, parameters.get(k));
                }
            }
        }
        return this;
    }

    /**
     * Clears all existing parameters
     *
     * @return itself
     */
    @SuppressWarnings("UnusedReturnValue")
    @NonNull
    public ParameterBuilder clearAll() {
        parameters.clear();
        return this;
    }

    /**
     * Create a {@link Map} with all the parameters
     *
     * @return all parameters added previously as a {@link Map}
     */
    @NonNull
    public Map<String, Object> asDictionary() {
        return Collections.unmodifiableMap(new HashMap<>(this.parameters));
    }

    /**
     * Creates a new instance of the builder using default values for login request, e.g. 'openid' for scope.
     *
     * @return a new builder
     */
    @NonNull
    public static ParameterBuilder newAuthenticationBuilder() {
        return newBuilder()
                .setScope(SCOPE_OPENID);
    }

    /**
     * Creates a new instance of the builder.
     * This builder wont have any default values
     *
     * @return a new builder
     */
    @NonNull
    public static ParameterBuilder newBuilder() {
        return newBuilder(new HashMap<String, Object>());
    }

    /**
     * Creates a new instance of the builder from some initial parameters.
     *
     * @param parameters initial parameters
     * @return a new builder
     */
    @NonNull
    public static ParameterBuilder newBuilder(@NonNull Map<String, Object> parameters) {
        return new ParameterBuilder(parameters);
    }

}
