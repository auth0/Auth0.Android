/*
 * AuthenticationException.java
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

package com.auth0.android.management;

import com.auth0.android.Auth0Exception;

import java.util.HashMap;
import java.util.Map;

public class ManagementException extends Auth0Exception {

    private static final String ERROR_KEY = "error";
    private static final String CODE_KEY = "code";
    private static final String DESCRIPTION_KEY = "description";
    private static final String ERROR_DESCRIPTION_KEY = "error_description";

    private static final String DEFAULT_MESSAGE = "An error occurred when trying to authenticate with the server.";

    private String code;
    private String description;
    private int statusCode;
    private Map<String, Object> values;


    public ManagementException(String message) {
        this(message, null);
    }

    public ManagementException(String message, Auth0Exception exception) {
        super(message, exception);
    }

    public ManagementException(String payload, int statusCode) {
        this(DEFAULT_MESSAGE);
        this.code = payload != null ? NON_JSON_ERROR : EMPTY_BODY_ERROR;
        this.description = payload != null ? payload : EMPTY_RESPONSE_BODY_DESCRIPTION;
        this.statusCode = statusCode;
    }

    public ManagementException(Map<String, Object> values) {
        this(DEFAULT_MESSAGE);
        this.values = new HashMap<>(values);

        String codeValue = (String) (this.values.containsKey(ERROR_KEY) ? this.values.get(ERROR_KEY) : this.values.get(CODE_KEY));
        this.code = codeValue != null ? codeValue : UNKNOWN_ERROR;
        this.description = (String) (this.values.containsKey(DESCRIPTION_KEY) ? this.values.get(DESCRIPTION_KEY) : this.values.get(ERROR_DESCRIPTION_KEY));
    }

    /**
     * Auth0 error code if the server returned one or an internal library code (e.g.: when the server could not be reached)
     *
     * @return the error code.
     */
    public String getCode() {
        return code != null ? code : UNKNOWN_ERROR;
    }

    /**
     * Http Response status code. Can have value of 0 if not set.
     *
     * @return the status code.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Description of the error.
     * important: You should avoid displaying description to the user, it's meant for debugging only.
     *
     * @return the error description.
     */
    public String getDescription() {
        if (description != null) {
            return description;
        }
        if (UNKNOWN_ERROR.equals(getCode())) {
            return String.format("Received error with code %s", getCode());
        }
        return "Failed with unknown error";
    }

    /**
     * Returns a value from the error map, if any.
     *
     * @param key key of the value to return
     * @return the value if found or null
     */
    public Object getValue(String key) {
        if (values == null) {
            return null;
        }
        return values.get(key);
    }

}
