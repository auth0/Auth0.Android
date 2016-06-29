/*
 * PermissionHandler.java
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
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v4.content.PermissionChecker;
import android.util.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PermissionHandler {

    private static final String TAG = PermissionHandler.class.getSimpleName();
    private int lastRequestCode = -100;

    public PermissionHandler() {
    }

    /**
     * Checks if the given Android Manifest Permission has been granted by the user to this application before.
     *
     * @param activity   the caller activity
     * @param permission to check availability for
     * @return true if the Android Manifest Permission is currently granted, false otherwise.
     */
    public boolean isPermissionGranted(@NonNull Activity activity, @NonNull String permission) {
        Log.v(TAG, String.format("Checking if %s permission is granted.", permission));
        int result = ContextCompat.checkSelfPermission(activity, permission);
        return result == PermissionChecker.PERMISSION_GRANTED;
    }

    /**
     * Checks if the given Android Manifest Permissions have been granted by the user to this application before.
     *
     * @param activity    the caller activity
     * @param permissions to check availability for
     * @return true if all the Android Manifest Permissions are currently granted, false otherwise.
     */
    public boolean areAllPermissionsGranted(@NonNull Activity activity, @NonNull String[] permissions) {
        for (String p : permissions) {
            if (!isPermissionGranted(activity, p)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Starts the request of the given Android Manifest Permissions.
     *
     * @param activity    the caller activity
     * @param permissions to request to the user
     * @param requestCode to use with this request
     * @return the Android Manifest Permissions that were previously declined by the user and may
     * now require an usage explanation
     */
    public List<String> requestPermissions(@NonNull Activity activity, @NonNull String[] permissions, int requestCode) {
        Log.v(TAG, String.format("Requesting user approval for %d permissions", permissions.length));
        List<String> permissionsToExplain = new ArrayList<>();
        for (String p : permissions) {
            if (ActivityCompat.shouldShowRequestPermissionRationale(activity, p)) {
                permissionsToExplain.add(p);
            }
        }
        if (!permissionsToExplain.isEmpty()) {
            Log.d(TAG, String.format("%d permissions need an explanation or were explicitly declined by the user.", permissionsToExplain.size()));
        }
        this.lastRequestCode = requestCode;
        ActivityCompat.requestPermissions(activity,
                permissions, requestCode);

        return permissionsToExplain;
    }

    /**
     * Called when there is a new response for a Android Manifest Permission request
     *
     * @param requestCode  received.
     * @param permissions  the Android Manifest Permissions that were requested
     * @param grantResults the grant result for each permission
     * @return the list of Android Manifest Permissions that were declined by the user.
     */
    public List<String> parseRequestResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode != this.lastRequestCode) {
            Log.d(TAG, String.format("The received Request Code doesn't match the expected one. Was %d but expected %d", requestCode, this.lastRequestCode));
            return Arrays.asList(permissions);
        } else if (permissions.length == 0 && grantResults.length == 0) {
            Log.w(TAG, "All the required permissions were declined by the user.");
            return Arrays.asList(permissions);
        }

        List<String> declinedPermissions = new ArrayList<>();
        for (int i = 0; i < permissions.length; i++) {
            if (grantResults[i] != PermissionChecker.PERMISSION_GRANTED) {
                declinedPermissions.add(permissions[i]);
            }
        }
        if (!declinedPermissions.isEmpty()) {
            Log.w(TAG, String.format("%d permissions were explicitly declined by the user.", declinedPermissions.size()));
        }
        return declinedPermissions;
    }
}
