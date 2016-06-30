package com.auth0.android.auth0;

import android.app.Activity;
import android.support.annotation.NonNull;

public interface PermissionProvider extends BaseProvider {

    /**
     * Defines which Android Manifest Permissions are required by this Identity Provider to work.
     * ex: Manifest.permission.GET_ACCOUNTS
     *
     * @return the required Android Manifest.permissions
     */
    String[] getRequiredAndroidPermissions();

    /**
     * Checks that the required permissions are granted before starting the authentication process,
     * and if everything is fine, the process begins. If some permissions were not granted before,
     * a Permission Request will be launched and the caller activity will receive its results on the
     * onRequestPermissionsResult method, from the ActivityCompat.OnRequestPermissionsResultCallback
     * interface.
     *
     * @param activity              a valid activity context.
     * @param callback              the callback to notify the authentication result
     * @param permissionRequestCode the code to use for the Permissions Request.
     */
    void start(@NonNull Activity activity, @NonNull AuthCallback callback, int permissionRequestCode);

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
    void onRequestPermissionsResult(@NonNull Activity activity, int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults);

}
