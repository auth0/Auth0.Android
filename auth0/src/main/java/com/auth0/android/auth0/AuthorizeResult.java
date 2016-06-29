/*
 * AuthorizeResult.java
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

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.Nullable;
import android.util.Log;

public class AuthorizeResult {

    private static final String TAG = AuthorizeResult.class.getSimpleName();
    private static final int MISSING_REQUEST_CODE = -100;
    private final int requestCode;
    private final int resultCode;
    private final Intent intent;

    /**
     * Wrapper for data received in OnActivityResult / OnNewIntent methods.
     *
     * @param requestCode the response request code
     * @param resultCode  the response result code
     * @param intent      the response intent.
     */
    public AuthorizeResult(int requestCode, int resultCode, @Nullable Intent intent) {
        this.requestCode = requestCode;
        this.resultCode = resultCode;
        this.intent = intent;
    }

    /**
     * Wrapper for data received in OnActivityResult / OnNewIntent methods.
     *
     * @param intent the response intent.
     */
    public AuthorizeResult(@Nullable Intent intent) {
        this.requestCode = MISSING_REQUEST_CODE;
        this.resultCode = Activity.RESULT_OK;
        this.intent = intent;
    }

    /**
     * Checks if the received data is valid and can be parsed.
     *
     * @param expectedRequestCode the request code this activity is expecting to receive
     * @return whether if the received uri data can be parsed or not.
     */
    public boolean isValid(int expectedRequestCode) {
        Uri uri = intent != null ? intent.getData() : null;
        if (uri == null) {
            Log.d(TAG, "Result is invalid: Received Intent's Uri is null.");
            return false;
        }

        if (requestCode == MISSING_REQUEST_CODE) {
            return true;
        }

        boolean fromRequest = getRequestCode() == expectedRequestCode;
        if (!fromRequest) {
            Log.d(TAG, String.format("Result is invalid: Received Request Code doesn't match the expected one. Was %d but expected %d", getRequestCode(), expectedRequestCode));
        }
        return fromRequest && resultCode == Activity.RESULT_OK;
    }

    public Intent getIntent() {
        return intent;
    }

    public int getRequestCode() {
        return requestCode;
    }

    public int getResultCode() {
        return resultCode;
    }
}
