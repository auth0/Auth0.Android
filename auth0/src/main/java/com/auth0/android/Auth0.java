/*
 * Auth0.java
 *
 * Copyright (c) 2016 Auth0 (http://auth0.com)
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

package com.auth0.android;


import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.auth0.android.auth0.BuildConfig;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.PasswordlessType;
import com.auth0.android.util.Telemetry;
import com.squareup.okhttp.HttpUrl;

/**
 * Represents your Auth0 account information (clientId {@literal &} domain),
 * and it's used to obtain clients for Auth0's APIs.
 * <pre>{@code
 * Auth0 auth0 = new Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN");
 * }</pre>
 * It is strongly encouraged that this SDK be used in OIDC Conformant mode.
 * When this mode is enabled, it will force the SDK to use Auth0's current authentication pipeline
 * and will prevent it from reaching legacy endpoints. By default is `false`
 * <pre>{@code
 * auth0.setOIDCConformant(true);
 * }</pre>
 * For more information, please see the <a href="https://auth0.com/docs/api-auth/tutorials/adoption">OIDC adoption guide</a>.
 *
 * @see Auth0#setOIDCConformant(boolean)
 */
public class Auth0 {

    private static final String AUTH0_US_CDN_URL = "https://cdn.auth0.com";
    private static final String DOT_AUTH0_DOT_COM = ".auth0.com";

    private final String clientId;
    private final HttpUrl domainUrl;
    private final HttpUrl configurationUrl;
    private Telemetry telemetry;
    private boolean oidcConformant;
    private boolean loggingEnabled;
    private boolean tls12Enforced;
    private int connectTimeoutInSeconds;
    private int readTimeoutInSeconds;
    private int writeTimeoutInSeconds;

    /**
     * Creates a new Auth0 instance with the 'com_auth0_client_id' and 'com_auth0_domain' values
     * defined in the project String resources file.
     * If the values are not found, IllegalArgumentException will raise.
     *
     * @param context a valid context
     */
    public Auth0(@NonNull Context context) {
        this(getResourceFromContext(context, "com_auth0_client_id"), getResourceFromContext(context, "com_auth0_domain"));
    }

    /**
     * Creates a new object using the Application's clientId {@literal &} domain
     *
     * @param clientId of your Auth0 application
     * @param domain   of your Auth0 account
     */
    public Auth0(@NonNull String clientId, @NonNull String domain) {
        this(clientId, domain, null);
    }

    /**
     * Creates a new object using clientId, domain and configuration domain.
     * Useful when using a on-premise auth0 server that is not in the public cloud,
     * otherwise we recommend using the constructor {@link #Auth0(String, String)}
     *
     * @param clientId            of your Auth0 application
     * @param domain              of your Auth0 account
     * @param configurationDomain where Auth0's configuration will be fetched. By default is Auth0 public cloud
     */
    public Auth0(@NonNull String clientId, @NonNull String domain, @Nullable String configurationDomain) {
        this.clientId = clientId;
        this.domainUrl = ensureValidUrl(domain);
        if (this.domainUrl == null) {
            throw new IllegalArgumentException(String.format("Invalid domain url: '%s'", domain));
        }
        this.configurationUrl = resolveConfiguration(configurationDomain, this.domainUrl);
        this.telemetry = new Telemetry(BuildConfig.LIBRARY_NAME, BuildConfig.VERSION_NAME);
    }

    /**
     * @return your Auth0 application client identifier
     */
    @NonNull
    public String getClientId() {
        return clientId;
    }

    /**
     * @return your Auth0 account domain url
     */
    @NonNull
    public String getDomainUrl() {
        return domainUrl.toString();
    }

    /**
     * @return your account configuration url
     */
    @NonNull
    public String getConfigurationUrl() {
        return configurationUrl.toString();
    }

    /**
     * Obtain the authorize URL for the current domain
     *
     * @return Url to call to perform the web flow of OAuth
     */
    @NonNull
    public String getAuthorizeUrl() {
        return domainUrl.newBuilder()
                .addEncodedPathSegment("authorize")
                .build()
                .toString();
    }

    /**
     * Obtain the logout URL for the current domain
     *
     * @return Url to call to perform the web logout
     */
    @NonNull
    public String getLogoutUrl() {
        return domainUrl.newBuilder()
                .addEncodedPathSegment("v2")
                .addEncodedPathSegment("logout")
                .build()
                .toString();
    }

    /**
     * @return Auth0 telemetry info sent in every request
     */
    @Nullable
    public Telemetry getTelemetry() {
        return telemetry;
    }

    /**
     * @return Auth0 request connectTimeoutInSeconds
     */
    public int getConnectTimeoutInSeconds() {
        return connectTimeoutInSeconds;
    }

    /**
     * @return Auth0 request readTimeoutInSeconds
     */
    public int getReadTimeoutInSeconds() {
        return readTimeoutInSeconds;
    }

    /**
     * @return Auth0 request writeTimeoutInSeconds
     */
    public int getWriteTimeoutInSeconds() {
        return writeTimeoutInSeconds;
    }

    /**
     * Setter for the Telemetry to send in every request to Auth0.
     *
     * @param telemetry to send in every request to Auth0.
     * @see #doNotSendTelemetry()
     */
    public void setTelemetry(@Nullable Telemetry telemetry) {
        this.telemetry = telemetry;
    }

    /**
     * Avoid sending telemetry in every request to Auth0
     */
    public void doNotSendTelemetry() {
        this.telemetry = null;
    }

    /**
     * It is strongly encouraged that this SDK be used in OIDC Conformant mode.
     * When this mode is enabled, it will force the SDK to use Auth0's current authentication pipeline
     * and will prevent it from reaching legacy endpoints. By default is {@code false}
     * For more information, please see the <a href="https://auth0.com/docs/api-auth/tutorials/adoption">OIDC adoption guide</a>.
     * <p>
     * This setting affects how authentication is performed in the following methods:
     * <ul>
     * <li>{@link AuthenticationAPIClient#login(String, String, String)}</li>
     * <li>{@link AuthenticationAPIClient#signUp(String, String, String)}</li>
     * <li>{@link AuthenticationAPIClient#signUp(String, String, String, String)}</li>
     * <li>{@link AuthenticationAPIClient#renewAuth(String)}</li>
     * <li>{@link AuthenticationAPIClient#passwordlessWithSMS(String, PasswordlessType, String)}</li>
     * <li>{@link AuthenticationAPIClient#passwordlessWithSMS(String, PasswordlessType)}</li>
     * <li>{@link AuthenticationAPIClient#passwordlessWithEmail(String, PasswordlessType)}</li>
     * <li>{@link AuthenticationAPIClient#passwordlessWithEmail(String, PasswordlessType, String)}</li>
     * <li>{@link AuthenticationAPIClient#loginWithPhoneNumber(String, String)}</li>
     * <li>{@link AuthenticationAPIClient#loginWithPhoneNumber(String, String, String)}</li>
     * <li>{@link AuthenticationAPIClient#loginWithEmail(String, String)}</li>
     * <li>{@link AuthenticationAPIClient#loginWithEmail(String, String, String)}</li>
     * </ul>
     *
     * @param enabled if Lock will use the Legacy Authentication API or the new OIDC Conformant Authentication API.
     */
    public void setOIDCConformant(boolean enabled) {
        this.oidcConformant = enabled;
    }

    /**
     * If the clients works in OIDC conformant mode or not
     *
     * @return whether the android client is OIDC conformant or not.
     */
    public boolean isOIDCConformant() {
        return oidcConformant;
    }

    /**
     * Getter for the HTTP logger is enabled or not.
     *
     * @return whether every Request, Response and other sensitive information should be logged or not.
     */
    public boolean isLoggingEnabled() {
        return loggingEnabled;
    }

    /**
     * Log every Request, Response and other sensitive information exchanged using the Auth0 APIs.
     * You shouldn't enable logging in release builds as it may leak sensitive information.
     *
     * @param enabled if every Request, Response and other sensitive information should be logged.
     */
    public void setLoggingEnabled(boolean enabled) {
        loggingEnabled = enabled;
    }

    /**
     * Getter for whether TLS 1.2 is enforced on devices with API 16-21.
     *
     * @return whether TLS 1.2 is enforced on devices with API 16-21.
     */
    public boolean isTLS12Enforced() {
        return tls12Enforced;
    }

    /**
     * Set whether to enforce TLS 1.2 on devices with API 16-21.
     *
     * @param enforced whether TLS 1.2 is enforced on devices with API 16-21.
     */
    public void setTLS12Enforced(boolean enforced) {
        tls12Enforced = enforced;
    }

    /**
     * Set the connection timeout for network requests.
     * By default, this value is 10 seconds.
     *
     * @param timeout the new timeout value in seconds
     */
    public void setConnectTimeoutInSeconds(int timeout) {
        this.connectTimeoutInSeconds = timeout;
    }

    /**
     * Set the read timeout for network requests.
     * By default, this value is 10 seconds.
     *
     * @param timeout the new timeout value in seconds
     */
    public void setReadTimeoutInSeconds(int timeout) {
        this.readTimeoutInSeconds = timeout;
    }

    /**
     * Set the write timeout for network requests.
     * By default, this value is 10 seconds.
     *
     * @param timeout the new timeout value in seconds
     */
    public void setWriteTimeoutInSeconds(int timeout) {
        this.writeTimeoutInSeconds = timeout;
    }

    private HttpUrl resolveConfiguration(@Nullable String configurationDomain, @NonNull HttpUrl domainUrl) {
        HttpUrl url = ensureValidUrl(configurationDomain);
        if (url == null) {
            final String host = domainUrl.host();
            if (host.endsWith(DOT_AUTH0_DOT_COM)) {
                String[] parts = host.split("\\.");
                if (parts.length > 3) {
                    url = HttpUrl.parse("https://cdn." + parts[parts.length - 3] + DOT_AUTH0_DOT_COM);
                } else {
                    url = HttpUrl.parse(AUTH0_US_CDN_URL);
                }
            } else {
                url = domainUrl;
            }
        }
        return url;
    }

    private HttpUrl ensureValidUrl(String url) {
        if (url == null) {
            return null;
        }
        String safeUrl = url.startsWith("http") ? url : "https://" + url;
        return HttpUrl.parse(safeUrl);
    }

    private static String getResourceFromContext(@NonNull Context context, String resName) {
        final int stringRes = context.getResources().getIdentifier(resName, "string", context.getPackageName());
        if (stringRes == 0) {
            throw new IllegalArgumentException(String.format("The 'R.string.%s' value it's not defined in your project's resources file.", resName));
        }
        return context.getString(stringRes);
    }
}
