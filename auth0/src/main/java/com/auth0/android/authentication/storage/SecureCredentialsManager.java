package com.auth0.android.authentication.storage;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.support.annotation.IntRange;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.annotation.VisibleForTesting;
import android.util.Base64;
import android.util.Log;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.internal.GsonProvider;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;

import static android.text.TextUtils.isEmpty;

/**
 * A safer alternative to the {@link CredentialsManager} class. A combination of RSA and AES keys is used to keep the values secure.
 * On devices running Android API 21 or up with a Secure LockScreen configured (PIN, Pattern, Password or Fingerprint) an extra
 * authentication step can be required.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
public class SecureCredentialsManager {

    private static final String TAG = SecureCredentialsManager.class.getSimpleName();

    private static final String KEY_CREDENTIALS = "com.auth0.credentials";
    private static final String KEY_EXPIRES_AT = "com.auth0.credentials_expires_at";
    private static final String KEY_CAN_REFRESH = "com.auth0.credentials_can_refresh";
    private static final String KEY_ALIAS = "com.auth0.key";

    private final AuthenticationAPIClient apiClient;
    private final Storage storage;
    private final CryptoUtil crypto;
    private final Gson gson;

    //Changeable by the user
    private boolean authenticateBeforeDecrypt;
    private int authenticationRequestCode = -1;
    private Activity activity;

    //State for retrying operations
    private BaseCallback<Credentials, CredentialsManagerException> decryptCallback;
    private Intent authIntent;


    @VisibleForTesting
    SecureCredentialsManager(@NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage, @NonNull CryptoUtil crypto) {
        this.apiClient = apiClient;
        this.storage = storage;
        this.crypto = crypto;
        this.gson = GsonProvider.buildGson();
        this.authenticateBeforeDecrypt = false;
    }

    /**
     * Creates a new SecureCredentialsManager to handle Credentials
     *
     * @param context   a valid context
     * @param apiClient the Auth0 Authentication API Client to handle token refreshment when needed.
     * @param storage   the storage implementation to use
     */
    public SecureCredentialsManager(@NonNull Context context, @NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage) {
        this(apiClient, storage, new CryptoUtil(context, storage, KEY_ALIAS));
    }

    /**
     * Require the user to authenticate using the configured LockScreen before accessing the credentials.
     * This feature is disabled by default and will only work if the device is running on Android version 21 or up and if the user
     * has configured a secure LockScreen (PIN, Pattern, Password or Fingerprint).
     * <p>
     * The activity passed as first argument here must override the {@link Activity#onActivityResult(int, int, Intent)} method and
     * call {@link SecureCredentialsManager#checkAuthenticationResult(int, int)} with the received parameters.
     *
     * @param activity    a valid activity context. Will be used in the authentication request to launch a LockScreen intent.
     * @param requestCode the request code to use in the authentication request. Must be a value between 1 and 255.
     * @param title       the text to use as title in the authentication screen. Passing null will result in using the OS's default value.
     * @param description the text to use as description in the authentication screen. On some Android versions it might not be shown. Passing null will result in using the OS's default value.
     * @return whether this device supports requiring authentication or not. This result can be ignored safely.
     */
    public boolean requireAuthentication(@NonNull Activity activity, @IntRange(from = 1, to = 255) int requestCode, @Nullable String title, @Nullable String description) {
        if (requestCode < 1 || requestCode > 255) {
            throw new IllegalArgumentException("Request code must a value between 1 and 255.");
        }
        KeyguardManager kManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);
        this.authIntent = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP ? kManager.createConfirmDeviceCredentialIntent(title, description) : null;
        this.authenticateBeforeDecrypt = ((Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && kManager.isDeviceSecure())
                || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && kManager.isKeyguardSecure()))
                && authIntent != null;
        if (authenticateBeforeDecrypt) {
            this.activity = activity;
            this.authenticationRequestCode = requestCode;
        }
        return authenticateBeforeDecrypt;
    }

    /**
     * Checks the result after showing the LockScreen to the user.
     * Must be called from the {@link Activity#onActivityResult(int, int, Intent)} method with the received parameters.
     * It's safe to call this method even if {@link SecureCredentialsManager#requireAuthentication(Activity, int, String, String)} was unsuccessful.
     *
     * @param requestCode the request code received in the onActivityResult call.
     * @param resultCode  the result code received in the onActivityResult call.
     * @return true if the result was handled, false otherwise.
     */
    public boolean checkAuthenticationResult(int requestCode, int resultCode) {
        if (requestCode != authenticationRequestCode || decryptCallback == null) {
            return false;
        }
        if (resultCode == Activity.RESULT_OK) {
            continueGetCredentials(decryptCallback);
        } else {
            decryptCallback.onFailure(new CredentialsManagerException("The user didn't pass the authentication challenge."));
            decryptCallback = null;
        }
        return true;
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

        Log.d(TAG, "Trying to encrypt the given data using the private key.");
        try {
            byte[] encrypted = crypto.encrypt(json.getBytes());
            String encryptedEncoded = Base64.encodeToString(encrypted, Base64.DEFAULT);
            storage.store(KEY_CREDENTIALS, encryptedEncoded);
            storage.store(KEY_EXPIRES_AT, expiresAt);
            storage.store(KEY_CAN_REFRESH, canRefresh);
        } catch (UnrecoverableContentException e) {
            //If keys were invalidated, a retry will work fine for the "save credentials" use case.
            saveCredentials(credentials);
        } catch (CryptoException e) {
            throw new CredentialsManagerException("An error occurred while encrypting the credentials.", e);
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
        Log.d(TAG, "Credentials were just removed from the storage");
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

    private void continueGetCredentials(final BaseCallback<Credentials, CredentialsManagerException> callback) {
        String encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS);
        byte[] encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT);

        String json;
        try {
            json = new String(crypto.decrypt(encrypted));
        } catch (CryptoException e) {
            if (e instanceof UnrecoverableContentException) {
                //If keys were invalidated, existing credentials will not be recoverable.
                clearCredentials();
            }
            callback.onFailure(new CredentialsManagerException("An error occurred while decrypting the existing credentials.", e));
            decryptCallback = null;
            return;
        }
        final Credentials credentials = gson.fromJson(json, Credentials.class);
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
            public void onSuccess(Credentials fresh) {
                //RefreshTokens don't expire. It should remain the same
                Credentials refreshed = new Credentials(fresh.getIdToken(), fresh.getAccessToken(), fresh.getType(), credentials.getRefreshToken(), fresh.getExpiresAt(), fresh.getScope());
                saveCredentials(refreshed);
                callback.onSuccess(refreshed);
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

}
