/*
 * MockBaseCallback.java
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

package com.auth0.android.util;

import android.app.Dialog;
import android.support.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.provider.AuthCallback;
import com.auth0.android.result.Credentials;

import java.util.concurrent.Callable;

public class MockAuthCallback implements AuthCallback {

    private AuthenticationException error;
    private Credentials credentials;
    private Dialog dialog;


    public Callable<AuthenticationException> error() {
        return new Callable<AuthenticationException>() {
            @Override
            public AuthenticationException call() {
                return error;
            }
        };
    }

    public Callable<Dialog> dialog() {
        return new Callable<Dialog>() {
            @Override
            public Dialog call() {
                return dialog;
            }
        };
    }

    public Callable<Credentials> credentials() {
        return new Callable<Credentials>() {
            @Override
            public Credentials call() {
                return credentials;
            }
        };
    }

    public AuthenticationException getError() {
        return error;
    }

    public Dialog getErrorDialog() {
        //unused
        return dialog;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    @Override
    public void onFailure(@NonNull Dialog dialog) {
        this.dialog = dialog;
    }

    @Override
    public void onFailure(@NonNull AuthenticationException exception) {
        this.error = exception;
    }

    @Override
    public void onSuccess(@NonNull Credentials credentials) {
        this.credentials = credentials;
    }
}
