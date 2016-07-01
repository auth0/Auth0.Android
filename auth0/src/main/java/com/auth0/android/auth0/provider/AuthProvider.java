/*
 * AuthProvider.java
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

package com.auth0.android.auth0.provider;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Intent;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.auth0.android.auth0.R;

import java.util.List;


/**
 * Class that can handle authentication flows for different cases, asking for the required
 * permissions before attempting to start the process.
 */
public abstract class AuthProvider {
    private static final String TAG = AuthProvider.class.getSimpleName();

    @NonNull
    private final PermissionHandler handler;
    protected AuthCallback callback;
    private int authenticationRequestCode;

    public AuthProvider() {
        this(new PermissionHandler());
    }

    AuthProvider(@NonNull PermissionHandler handler) {
        this.handler = handler;
    }

    /**
     * Checks that the required permissions are granted before starting the authentication process,
     * and if everything is fine, the process begins. If some permissions were not granted before,
     * a Permission Request will be launched and the caller activity will receive its results on the
     * onRequestPermissionsResult method, from the ActivityCompat.OnRequestPermissionsResultCallback
     * interface.
     *
     * @param activity                  a valid activity context.
     * @param callback                  the callback to notify the authentication result
     * @param permissionRequestCode     the code to use in the Permissions Request.
     * @param authenticationRequestCode the code to use in the Authentication Request.
     */
    public void start(@NonNull Activity activity, @NonNull AuthCallback callback, int permissionRequestCode, int authenticationRequestCode) {
        this.callback = callback;
        this.authenticationRequestCode = authenticationRequestCode;

        if (checkPermissions(activity)) {
            Log.v(TAG, "All permissions were already granted, the authentication flow is starting.");
            requestAuth(activity, authenticationRequestCode);
        } else {
            Log.d(TAG, "Some permissions were not previously granted, requesting them now.");
            requestPermissions(activity, permissionRequestCode);
        }
    }

    /**
     * Starts the authentication flow on the Identity Provider. The connection name is specified
     * by the getConnectionName method.
     * All the required Android permissions had already been granted when Start was called, so
     * it's safe to use them directly.
     *
     * @param activity    a valid activity context.
     * @param requestCode to use in the Authentication request
     */
    protected abstract void requestAuth(Activity activity, int requestCode);

    /**
     * Stops the authentication process (even if it's in progress).
     */
    public void stop() {
    }

    /**
     * Removes any session information stored in the object.
     */
    public void clearSession() {
        callback = null;
    }

    /**
     * Finishes the authentication flow by passing the data received in the activity's onActivityResult() callback.
     * The final authentication result will be delivered to the callback specified when calling start().
     *
     * @param requestCode the request code received on the onActivityResult() call
     * @param resultCode  the result code received on the onActivityResult() call
     * @param intent      the data received on the onActivityResult() call
     * @return true if a result was expected and has a valid format, or false if not.
     */
    public abstract boolean authorize(int requestCode, int resultCode, @Nullable Intent intent);

    /**
     * Finishes the authentication flow by passing the data received in the activity's onNewIntent() callback.
     * The final authentication result will be delivered to the callback specified when calling start().
     *
     * @param intent the data received on the onNewIntent() call
     * @return true if a result was expected and has a valid format, or false if not.
     */
    public abstract boolean authorize(@Nullable Intent intent);

    /**
     * Defines which Android Manifest Permissions are required by this Identity Provider to work.
     * ex: Manifest.permission.GET_ACCOUNTS
     *
     * @return the required Android Manifest.permissions
     */
    public abstract String[] getRequiredAndroidPermissions();

    /**
     * Checks if all the required Android Manifest.permissions have already been granted.
     *
     * @param activity a valid activity context.
     * @return true if all the requested permissions are already granted, false otherwise.
     */
    private boolean checkPermissions(Activity activity) {
        String[] permissions = getRequiredAndroidPermissions();
        return handler.areAllPermissionsGranted(activity, permissions);
    }

    /**
     * Starts the async Permission Request. The caller activity will be notified of the result on the
     * onRequestPermissionsResult method, from the ActivityCompat.OnRequestPermissionsResultCallback
     * interface.
     *
     * @param activity    a valid activity context. It will receive the permissions
     *                    request result on the onRequestPermissionsResult method.
     * @param requestCode the code to use for the Permissions Request.
     */
    private void requestPermissions(Activity activity, int requestCode) {
        String[] permissions = getRequiredAndroidPermissions();
        handler.requestPermissions(activity, permissions, requestCode);
    }

    /**
     * Should be called from the activity that initiated the Android Manifest.permission request,
     * when the method #onRequestPermissionResult is called on that activity. If all the permissions
     * are now granted, the authentication flow will begin.
     *
     * @param activity     a valid activity context.
     * @param requestCode  the request code
     * @param permissions  the requested permissions
     * @param grantResults the grant results for each permission
     */
    public void onRequestPermissionsResult(@NonNull Activity activity, int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        List<String> declinedPermissions = handler.parseRequestResult(requestCode, permissions, grantResults);

        if (declinedPermissions.isEmpty()) {
            Log.v(TAG, "All permissions were granted!");
            requestAuth(activity, authenticationRequestCode);
        } else if (callback != null) {
            Log.e(TAG, "Permission Request failed. Some permissions were not granted!");
            String message = String.format(activity.getString(R.string.com_auth0_lock_permission_missing_description), declinedPermissions);
            Dialog permissionDialog = new AlertDialog.Builder(activity)
                    .setTitle(R.string.com_auth0_lock_permission_missing_title)
                    .setMessage(message)
                    .setPositiveButton(android.R.string.ok, null)
                    .create();
            callback.onFailure(permissionDialog);
        }
    }

}