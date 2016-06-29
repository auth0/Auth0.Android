/*
 * AuthCallback.java
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

package com.auth0.android.auth0;

import android.app.Dialog;
import android.support.annotation.NonNull;
import android.support.annotation.StringRes;

import com.auth0.android.auth0.lib.authentication.result.Credentials;

/**
 * Callback called on success/failure of an Identity Provider authentication.
 * Only one of the success or failure methods will be called for a single authentication request.
 */
public interface AuthCallback {

    /**
     * Called when the failure reason is displayed in a {@link android.app.Dialog}.
     *
     * @param dialog error dialog
     */
    void onFailure(@NonNull Dialog dialog);

    /**
     * Called with a title and message resource that describes the error. If a cause is available it will be sent or it will be {@code null}
     *
     * @param titleResource   title resource
     * @param messageResource message resource
     * @param cause           cause of the error
     */
    void onFailure(@StringRes int titleResource, @StringRes int messageResource, Throwable cause);

    /**
     * Called when the authentication is successful using web authentication against Auth0
     *
     * @param credentials Auth0 credentials information (id_token, refresh_token, etc).
     */
    void onSuccess(@NonNull Credentials credentials);
}