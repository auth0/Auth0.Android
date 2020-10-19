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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;

import java.util.concurrent.Callable;

public class MockAuthenticationCallback<T> implements AuthenticationCallback<T> {

    private AuthenticationException error;
    private T payload;

    @Override
    public void onFailure(@NonNull AuthenticationException error) {
        this.error = error;
    }

    @Override
    public void onSuccess(@Nullable T payload) {
        this.payload = payload;
    }

    public Callable<AuthenticationException> error() {
        return new Callable<AuthenticationException>() {
            @Override
            public AuthenticationException call() {
                return error;
            }
        };
    }

    public Callable<T> payload() {
        return new Callable<T>() {
            @Override
            public T call() {
                return payload;
            }
        };
    }

    public AuthenticationException getError() {
        return error;
    }

    public T getPayload() {
        return payload;
    }
}
