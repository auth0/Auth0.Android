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


import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.auth0.android.auth0.BuildConfig;
import com.auth0.android.util.Telemetry;
import com.squareup.okhttp.HttpUrl;

/**
 * Represents your Auth0 account information (clientId & domain),
 * and it's used to obtain clients for Auth0's APIs.
 * <pre>{@code
 * Auth0 auth0 = new Auth0("YOUR_CLIENT_ID", "YOUR_DOMAIN");
 * }</pre>
 */
public class Auth0 {

    private static final String AUTH0_US_CDN_URL = "https://cdn.auth0.com";
    private static final String DOT_AUTH0_DOT_COM = ".auth0.com";

    private final String clientId;
    private final HttpUrl domainUrl;
    private final HttpUrl configurationUrl;
    private Telemetry telemetry;

    /**
     * Creates a new object using clientId & domain
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
    public String getClientId() {
        return clientId;
    }

    /**
     * @return your Auth0 account domain url
     */
    public String getDomainUrl() {
        return domainUrl.toString();
    }

    /**
     * @return your account configuration url
     */
    public String getConfigurationUrl() {
        return configurationUrl.toString();
    }

    /**
     * @return Url to perform the web flow of OAuth
     */
    public String getAuthorizeUrl() {
        return domainUrl.newBuilder()
                .addEncodedPathSegment("authorize")
                .build()
                .toString();
    }

    /**
     * @return Auth0 telemetry info sent in every request
     */
    public Telemetry getTelemetry() {
        return telemetry;
    }


    /**
     * Setter for the Telemetry to send in every request to Auth0.
     *
     * @param telemetry to send in every request to Auth0
     */
    public void setTelemetry(Telemetry telemetry) {
        this.telemetry = telemetry;
    }

    /**
     * Avoid sending telemetry in every request to Auth0
     */
    public void doNotSendTelemetry() {
        this.telemetry = null;
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
}
