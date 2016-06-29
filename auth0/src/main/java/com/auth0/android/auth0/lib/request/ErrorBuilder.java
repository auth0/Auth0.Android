package com.auth0.android.auth0.lib.request;

import com.auth0.android.auth0.lib.Auth0Exception;

import java.util.Map;

public interface ErrorBuilder<U extends Auth0Exception> {

    /**
     * @param message the description
     * @return a new exception instance
     */
    U from(String message);

    /**
     * @param message   the description
     * @param exception the exception raised.
     * @return a new exception instance
     */
    U from(String message, Auth0Exception exception);

    /**
     * @param values the payload values
     * @return a new exception instance
     */
    U from(Map<String, Object> values);

    /**
     * @param payload    the String payload from the response.
     * @param statusCode the http status code.
     * @return a new exception instance
     */
    U from(String payload, int statusCode);

}
