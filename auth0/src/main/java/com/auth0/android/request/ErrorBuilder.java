package com.auth0.android.request;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.auth0.android.Auth0Exception;

import java.util.Map;

public interface ErrorBuilder<U extends Auth0Exception> {

    /**
     * @param message the description
     * @return a new exception instance
     */
    @NonNull
    U from(@NonNull String message);

    /**
     * @param message   the description
     * @param exception the exception raised.
     * @return a new exception instance
     */
    @NonNull
    U from(@NonNull String message, @NonNull Auth0Exception exception);

    /**
     * @param values the payload values
     * @return a new exception instance
     */
    @NonNull
    U from(@NonNull Map<String, Object> values);

    /**
     * @param payload    the String payload from the response.
     * @param statusCode the http status code.
     * @return a new exception instance
     */
    @NonNull
    U from(@Nullable String payload, int statusCode);

}
