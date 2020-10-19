/*
 * Auth0Exception.java
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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Base Exception for any error found during a request to Auth0's API
 */
public class Auth0Exception extends RuntimeException {

    public static final String UNKNOWN_ERROR = "a0.sdk.internal_error.unknown";
    @SuppressWarnings("WeakerAccess")
    public static final String NON_JSON_ERROR = "a0.sdk.internal_error.plain";
    @SuppressWarnings("WeakerAccess")
    public static final String EMPTY_BODY_ERROR = "a0.sdk.internal_error.empty";
    @SuppressWarnings("WeakerAccess")
    public static final String EMPTY_RESPONSE_BODY_DESCRIPTION = "Empty response body";

    public Auth0Exception(@NonNull String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public Auth0Exception(@NonNull String message) {
        super(message);
    }
}
