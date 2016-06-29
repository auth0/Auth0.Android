/*
 * CallbackHelper.java
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

import android.net.Uri;
import android.support.annotation.NonNull;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

public class CallbackHelper {

    private static final String TAG = CallbackHelper.class.getSimpleName();
    private static final String REDIRECT_URI_FORMAT = "%s/android/%s/callback";
    private final String packageName;

    public CallbackHelper(@NonNull String packageName) {
        this.packageName = packageName;
    }

    /**
     * Generates the callback URI for the given domain.
     *
     * @return the callback URI.
     */
    public String getCallbackURI(@NonNull String domain) {
        String uri = String.format(REDIRECT_URI_FORMAT, domain, packageName);
        Log.v(TAG, "The Callback URI is: " + uri);
        return uri;
    }

    public Map<String, String> getValuesFromUri(@NonNull Uri uri) {
        return asMap(uri.getQuery() != null ? uri.getQuery() : uri.getFragment());
    }

    private Map<String, String> asMap(@NonNull String valueString) {
        final String[] entries = valueString.length() > 0 ? valueString.split("&") : new String[]{};
        Map<String, String> values = new HashMap<>(entries.length);
        for (String entry : entries) {
            final String[] value = entry.split("=");
            if (value.length == 2) {
                values.put(value[0], value[1]);
            }
        }
        return values;
    }
}