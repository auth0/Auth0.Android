package com.auth0.android;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.squareup.okhttp.HttpUrl;

/**
 * Mock implementation of {@linkplain Auth0} for tests.
 * This implementation does not enforce HTTPS, and should be removed after tests are able
 * to run with the MockWebServer using HTTPS.
 */
public class MockAuth0 extends Auth0 {

    public MockAuth0(@NonNull String clientId, @NonNull String domain) {
        this(clientId, domain, null);
    }

    public MockAuth0(@NonNull String clientId, @NonNull String domain, @Nullable String configurationDomain) {
        super(clientId, domain, configurationDomain);
    }

    /**
     * Returns the result of calling of {@linkplain HttpUrl#parse(String)} on the provided string.
     * Overriden to not enforce HTTPS for tests.
     *
     * @param url The URL to parse
     * @return The parsed URL, or null if the {@code url} parameter was null.
     */
    @Override
    HttpUrl ensureValidUrl(String url) {
        /*
        TODO [SDK-2221]: get MockWebServer running with HTTPS and remove this class. Should be done
         after updating to more recent versions of OkHttp
         */
        if (url == null) {
            return null;
        }
        return HttpUrl.parse(url);
    }
}
