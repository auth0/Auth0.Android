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

package com.auth0.android.auth0;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.support.annotation.NonNull;
import android.util.Log;

import java.util.List;


/**
 * Class that can handle authentication flows for different cases, asking for the required
 * permissions before attempting to start the process.
 */
public abstract class AuthProvider {
    public static final String TAG = AuthProvider.class.getSimpleName();

    @NonNull
    protected AuthCallback callback;
    @NonNull
    protected final PermissionHandler handler;

    private String lastConnectionName;

    public AuthProvider(@NonNull AuthCallback callback) {
        this(callback, new PermissionHandler());
    }

    AuthProvider(@NonNull AuthCallback callback, @NonNull PermissionHandler handler) {
        this.callback = callback;
        this.handler = handler;
    }

    /**
     * Checks that the required permissions are granted before starting the authentication process,
     * and if everything is fine, the process begins. If some permissions were not granted before,
     * a Permission Request will be launched and the caller activity will receive its results on the
     * onRequestPermissionsResult method, from the ActivityCompat.OnRequestPermissionsResultCallback
     * interface.
     *
     * @param activity       a valid activity context.
     * @param connectionName the connection name to use.
     * @param requestCode    the code to use for the Permissions Request.
     */
    public void start(Activity activity, String connectionName, int requestCode) {
        if (checkPermissions(activity)) {
            Log.v(TAG, "All permissions were already granted, the authentication flow is starting.");
            requestAuth(activity, connectionName);
        } else {
            Log.d(TAG, "Some permissions were not previously granted, requesting them now.");
            lastConnectionName = connectionName;
            requestPermissions(activity, requestCode);
        }
    }

    /**
     * Starts the authentication flow on the Identity Provider for the given connection name.
     * All the required Android permissions had already been granted when Start was called, so
     * it's safe to use them directly.
     *
     * @param activity       a valid activity context.
     * @param connectionName the connection name to use.
     */
    protected abstract void requestAuth(Activity activity, String connectionName);

    /**
     * Stops the authentication process (even if it's in progress).
     */
    @SuppressWarnings("unused")
    public void stop() {
    }

    /**
     * Removes any session information stored in the object.
     */
    @SuppressWarnings("unused")
    public void clearSession() {
    }

    /**
     * Finishes the auth flow by parsing the AuthorizeResult. The authentication result
     * will be notified to the callback.
     *
     * @param activity a valid activity context.
     * @param result   the result received in the activity.
     * @return if the result is valid or not. Please note, this does not means that the
     * user is authenticated. The authentication result will be notified to the callback.
     */
    public abstract boolean authorize(Activity activity, @NonNull AuthorizeResult result);

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
    @SuppressWarnings("unused")
    public void onRequestPermissionsResult(Activity activity, int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        List<String> declinedPermissions = handler.parseRequestResult(requestCode, permissions, grantResults);

        if (declinedPermissions.isEmpty()) {
            Log.v(TAG, "All permissions were granted!");
            requestAuth(activity, lastConnectionName);
        } else {
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