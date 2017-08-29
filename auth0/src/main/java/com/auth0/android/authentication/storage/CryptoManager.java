package com.auth0.android.authentication.storage;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.support.annotation.VisibleForTesting;
import android.util.Base64;
import android.util.Log;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;

import static android.text.TextUtils.isEmpty;

@SuppressWarnings({"WeakerAccess", "unused"})
@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
public class CryptoManager {

    private static final String TAG = CryptoManager.class.getSimpleName();
    private static final int DEF_REQ_CODE = 4;

    private static final String KEY_CREDENTIALS = "com.auth0.credentials";
    private static final String KEY_EXPIRES_AT = "com.auth0.credentials_expires_at";
    private static final String KEY_CAN_REFRESH = "com.auth0.credentials_can_refresh";
    private static final String KEY_ALIAS = "com.auth0.key";

    private final Activity activity;
    private final Storage storage;
    private final AuthenticationAPIClient apiClient;
    private final Gson gson;
    private final CryptoUtil crypto;
    private final boolean authenticateBeforeDecrypt;

    //State for retrying operations
    private BaseCallback<Credentials, CredentialsManagerException> decryptCallback;
    private Intent authIntent;
    private int authenticationRequestCode = DEF_REQ_CODE;


    @VisibleForTesting
    CryptoManager(@NonNull Activity activity, @NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage, boolean requireAuthentication, @NonNull CryptoUtil crypto) {
        this.activity = activity;
        this.apiClient = apiClient;
        this.storage = storage;
        this.gson = new Gson();
        this.crypto = crypto;
        KeyguardManager kManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);
        //TODO: Allow to customize the title and description
        this.authIntent = kManager.createConfirmDeviceCredentialIntent(null, null);
        this.authenticateBeforeDecrypt = requireAuthentication &&
                (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && kManager.isDeviceSecure()
                        || Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && kManager.isKeyguardSecure() && authIntent != null);
        if (!authenticateBeforeDecrypt) {
            Log.w(TAG, "This device lacks a configured LockScreen. Data will be encrypted but not protected.");
        }
    }

    /**
     * Creates a new CryptoManager to handle Credentials
     *
     * @param activity              a valid activity context
     * @param apiClient             the Auth0 Authentication API Client to handle token refreshment when needed.
     * @param storage               the storage implementation to use
     * @param requireAuthentication whether the user must authenticate using the LockScreen before accessing the credentials.
     */
    public CryptoManager(@NonNull Activity activity, @NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage, boolean requireAuthentication) {
        this(activity, apiClient, storage, requireAuthentication, new CryptoUtil(activity, storage, KEY_ALIAS));
    }


    private void continueGetCredentials(final BaseCallback<Credentials, CredentialsManagerException> callback) {
        Log.e(TAG, "Trying to decrypt the stored data using the public key.");
        String encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS);
        byte[] encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT);

        String json;
        try {
            json = new String(crypto.decrypt(encrypted));
        } catch (CredentialsManagerException e) {
            callback.onFailure(e);
            return;
        }
        Credentials credentials = gson.fromJson(json, Credentials.class);
        if (isEmpty(credentials.getAccessToken()) && isEmpty(credentials.getIdToken()) || credentials.getExpiresAt() == null) {
            callback.onFailure(new CredentialsManagerException("No Credentials were previously set."));
            decryptCallback = null;
            return;
        }
        if (credentials.getExpiresAt().getTime() > getCurrentTimeInMillis()) {
            callback.onSuccess(credentials);
            decryptCallback = null;
            return;
        }
        if (credentials.getRefreshToken() == null) {
            callback.onFailure(new CredentialsManagerException("No Credentials were previously set."));
            decryptCallback = null;
            return;
        }

        Log.d(TAG, "Credentials have expired. Renewing them now...");
        apiClient.renewAuth(credentials.getRefreshToken()).start(new AuthenticationCallback<Credentials>() {
            @Override
            public void onSuccess(Credentials refreshedCredentials) {
                callback.onSuccess(refreshedCredentials);
                decryptCallback = null;
            }

            @Override
            public void onFailure(AuthenticationException error) {
                callback.onFailure(new CredentialsManagerException("An error occurred while trying to use the Refresh Token to renew the Credentials.", error));
                decryptCallback = null;
            }
        });
    }

    @VisibleForTesting
    long getCurrentTimeInMillis() {
        return System.currentTimeMillis();
    }


    /**
     * Checks the result after showing the LockScreen to the user.
     * Must be called from the {@link Activity#onActivityResult(int, int, Intent)} method with the received parameters.
     *
     * @param requestCode the request code of the authentication.
     * @param resultCode  the result code of the authentication.
     * @return true if the result was handled. False otherwise. If no LockScreen result is expected by this class it will return false.
     */
    public boolean checkAuthenticationResult(int requestCode, int resultCode) {
        if (requestCode != authenticationRequestCode || decryptCallback == null) {
            return false;
        }
        if (resultCode == Activity.RESULT_OK) {
            continueGetCredentials(decryptCallback);
        } else {
            decryptCallback = null;
        }
        return true;
    }

    /**
     * Changes the request code used to prompt the user for Authentication.
     *
     * @param requestCode the new request code to use. Must be between 1 and 100.
     */
    public void setAuthenticationRequestCode(int requestCode) {
        if (requestCode < 1 || requestCode > 100) {
            throw new IllegalArgumentException("The new request code must have a value between 1 and 100");
        }
        this.authenticationRequestCode = requestCode;
    }

    /**
     * Saves the given credentials in the Storage.
     *
     * @param credentials the credentials to save.
     * @throws CredentialsManagerException if the credentials couldn't be encrypted.
     */
    public void saveCredentials(@NonNull Credentials credentials) throws CredentialsManagerException {
        if ((isEmpty(credentials.getAccessToken()) && isEmpty(credentials.getIdToken())) || credentials.getExpiresAt() == null) {
            throw new CredentialsManagerException("Credentials must have a valid date of expiration and a valid access_token or id_token value.");
        }

        String json = gson.toJson(credentials);
        long expiresAt = credentials.getExpiresAt().getTime();
        boolean canRefresh = !isEmpty(credentials.getRefreshToken());

        Log.e(TAG, "Trying to encrypt the given data using the private key.");
        try {
            byte[] encrypted = crypto.encrypt(json.getBytes());
            String encryptedEncoded = Base64.encodeToString(encrypted, Base64.DEFAULT);
            storage.store(KEY_CREDENTIALS, encryptedEncoded);
            storage.store(KEY_EXPIRES_AT, expiresAt);
            storage.store(KEY_CAN_REFRESH, canRefresh);
        } catch (Exception e) {
            throw new CredentialsManagerException("Couldn't encrypt the credentials", e);
        }
    }

    /**
     * Tries to obtain the credentials from the Storage.
     * If a LockScreen is setup the user will be asked to authenticate before accessing the credentials. Your activity must override the
     * {@link Activity#onActivityResult(int, int, Intent)} method and call {@link #checkAuthenticationResult(int, int)} with the received values.
     *
     * @param callback the callback to receive the result in.
     */
    public void getCredentials(@NonNull BaseCallback<Credentials, CredentialsManagerException> callback) {
        if (!hasValidCredentials()) {
            callback.onFailure(new CredentialsManagerException("No Credentials were previously set."));
            return;
        }

        if (authenticateBeforeDecrypt) {
            Log.d(TAG, "Authentication is required to read the Credentials. Showing the LockScreen.");
            decryptCallback = callback;
            activity.startActivityForResult(authIntent, authenticationRequestCode);
            return;
        }
        continueGetCredentials(callback);
    }


    /**
     * Delete the stored credentials
     */
    public void clearCredentials() {
        storage.remove(KEY_CREDENTIALS);
        storage.remove(KEY_EXPIRES_AT);
        storage.remove(KEY_CAN_REFRESH);
        Log.d(TAG, "Credentials were removed from the storage");
    }

    /**
     * Returns whether this manager contains a valid non-expired pair of credentials.
     *
     * @return whether this manager contains a valid non-expired pair of credentials or not.
     */
    public boolean hasValidCredentials() {
        String encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS);
        Long expiresAt = storage.retrieveLong(KEY_EXPIRES_AT);
        Boolean canRefresh = storage.retrieveBoolean(KEY_CAN_REFRESH);
        return !(isEmpty(encryptedEncoded) ||
                expiresAt == null ||
                expiresAt <= getCurrentTimeInMillis() && (canRefresh == null || !canRefresh));
    }

}
