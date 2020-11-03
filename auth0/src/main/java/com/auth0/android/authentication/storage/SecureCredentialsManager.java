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

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.JWT;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.request.internal.GsonProvider;
import com.auth0.android.result.Credentials;
import com.auth0.android.util.Clock;
import com.google.gson.Gson;

import java.util.Arrays;
import java.util.Date;

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
    private static final String KEY_EXPIRES_AT = "com.auth0.credentials_access_token_expires_at";
    private static final String KEY_CACHE_EXPIRES_AT = "com.auth0.credentials_expires_at";
    private static final String KEY_CAN_REFRESH = "com.auth0.credentials_can_refresh";
    private static final String KEY_CRYPTO_ALIAS = "com.auth0.manager_key_alias";
    @VisibleForTesting
    static final String KEY_ALIAS = "com.auth0.key";

    private final AuthenticationAPIClient apiClient;
    private final Storage storage;
    private final CryptoUtil crypto;
    private final Gson gson;
    private final JWTDecoder jwtDecoder;
    private Clock clock;

    //Changeable by the user
    private boolean authenticateBeforeDecrypt;
    private int authenticationRequestCode = -1;
    private Activity activity;

    //State for retrying operations
    private BaseCallback<Credentials, CredentialsManagerException> decryptCallback;
    private Intent authIntent;
    private String scope;
    private int minTtl;


    @VisibleForTesting
    SecureCredentialsManager(@NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage, @NonNull CryptoUtil crypto, @NonNull JWTDecoder jwtDecoder) {
        this.apiClient = apiClient;
        this.storage = storage;
        this.crypto = crypto;
        this.gson = GsonProvider.buildGson();
        this.authenticateBeforeDecrypt = false;
        this.jwtDecoder = jwtDecoder;
        this.clock = new ClockImpl();
    }

    /**
     * Creates a new SecureCredentialsManager to handle Credentials
     *
     * @param context   a valid context
     * @param apiClient the Auth0 Authentication API Client to handle token refreshment when needed.
     * @param storage   the storage implementation to use
     */
    public SecureCredentialsManager(@NonNull Context context, @NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage) {
        this(apiClient, storage, new CryptoUtil(context, storage, KEY_ALIAS), new JWTDecoder());
    }

    /**
     * Updates the clock instance used for expiration verification purposes.
     * The use of this method can help on situations where the clock comes from an external synced source.
     * The default implementation uses the time returned by {@link System#currentTimeMillis()}.
     *
     * @param clock the new clock instance to use.
     */
    public void setClock(@NonNull Clock clock) {
        this.clock = clock;
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
            throw new IllegalArgumentException("Request code must be a value between 1 and 255.");
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
            continueGetCredentials(scope, minTtl, decryptCallback);
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
     * @throws CredentialsManagerException if the credentials couldn't be encrypted. Some devices are not compatible at all with the cryptographic
     *                                     implementation and will have {@link CredentialsManagerException#isDeviceIncompatible()} return true.
     */
    public void saveCredentials(@NonNull Credentials credentials) throws CredentialsManagerException {
        if ((isEmpty(credentials.getAccessToken()) && isEmpty(credentials.getIdToken())) || credentials.getExpiresAt() == null) {
            throw new CredentialsManagerException("Credentials must have a valid date of expiration and a valid access_token or id_token value.");
        }

        long cacheExpiresAt = calculateCacheExpiresAt(credentials);
        String json = gson.toJson(credentials);
        boolean canRefresh = !isEmpty(credentials.getRefreshToken());

        Log.d(TAG, "Trying to encrypt the given data using the private key.");
        try {
            byte[] encrypted = crypto.encrypt(json.getBytes());
            String encryptedEncoded = Base64.encodeToString(encrypted, Base64.DEFAULT);
            storage.store(KEY_CREDENTIALS, encryptedEncoded);
            storage.store(KEY_EXPIRES_AT, credentials.getExpiresAt().getTime());
            storage.store(KEY_CACHE_EXPIRES_AT, cacheExpiresAt);
            storage.store(KEY_CAN_REFRESH, canRefresh);
            storage.store(KEY_CRYPTO_ALIAS, KEY_ALIAS);
        } catch (IncompatibleDeviceException e) {
            throw new CredentialsManagerException(String.format("This device is not compatible with the %s class.", SecureCredentialsManager.class.getSimpleName()), e);
        } catch (CryptoException e) {
            /*
             * If the keys were invalidated in the call above a good new pair is going to be available
             * to use on the next call. We clear any existing credentials so #hasValidCredentials returns
             * a true value. Retrying this operation will succeed.
             */
            clearCredentials();
            throw new CredentialsManagerException("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. Please, try saving the credentials again.", e);
        }
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's {@link BaseCallback#onSuccess(Object)} method will be called with the result.
     * If something unexpected happens, the {@link BaseCallback#onFailure(Auth0Exception)} method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have {@link CredentialsManagerException#isDeviceIncompatible()} return true.
     * <p>
     * If a LockScreen is setup and {@link #requireAuthentication(Activity, int, String, String)} was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the {@link Activity#onActivityResult(int, int, Intent)} method and call
     * {@link #checkAuthenticationResult(int, int)} with the received values.
     *
     * @param callback the callback to receive the result in.
     */
    public void getCredentials(@NonNull BaseCallback<Credentials, CredentialsManagerException> callback) {
        getCredentials(null, 0, callback);
    }

    /**
     * Tries to obtain the credentials from the Storage. The callback's {@link BaseCallback#onSuccess(Object)} method will be called with the result.
     * If something unexpected happens, the {@link BaseCallback#onFailure(Auth0Exception)} method will be called with the error. Some devices are not compatible
     * at all with the cryptographic implementation and will have {@link CredentialsManagerException#isDeviceIncompatible()} return true.
     * <p>
     * If a LockScreen is setup and {@link #requireAuthentication(Activity, int, String, String)} was called, the user will be asked to authenticate before accessing
     * the credentials. Your activity must override the {@link Activity#onActivityResult(int, int, Intent)} method and call
     * {@link #checkAuthenticationResult(int, int)} with the received values.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param callback the callback to receive the result in.
     */
    public void getCredentials(@Nullable String scope, int minTtl, @NonNull BaseCallback<Credentials, CredentialsManagerException> callback) {
        if (!hasValidCredentials(minTtl)) {
            callback.onFailure(new CredentialsManagerException("No Credentials were previously set."));
            return;
        }

        if (authenticateBeforeDecrypt) {
            Log.d(TAG, "Authentication is required to read the Credentials. Showing the LockScreen.");
            this.decryptCallback = callback;
            this.scope = scope;
            this.minTtl = minTtl;
            activity.startActivityForResult(authIntent, authenticationRequestCode);
            return;
        }
        continueGetCredentials(scope, minTtl, callback);
    }

    /**
     * Delete the stored credentials
     */
    public void clearCredentials() {
        storage.remove(KEY_CREDENTIALS);
        storage.remove(KEY_EXPIRES_AT);
        storage.remove(KEY_CACHE_EXPIRES_AT);
        storage.remove(KEY_CAN_REFRESH);
        storage.remove(KEY_CRYPTO_ALIAS);
        Log.d(TAG, "Credentials were just removed from the storage");
    }

    /**
     * Returns whether this manager contains a valid non-expired pair of credentials.
     *
     * @return whether this manager contains a valid non-expired pair of credentials or not.
     */
    public boolean hasValidCredentials() {
        return hasValidCredentials(0);
    }

    /**
     * Returns whether this manager contains a valid non-expired pair of credentials.
     *
     * @param minTtl the minimum time in seconds that the access token should last before expiration.
     * @return whether this manager contains a valid non-expired pair of credentials or not.
     */
    public boolean hasValidCredentials(long minTtl) {
        String encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS);
        Long expiresAt = storage.retrieveLong(KEY_EXPIRES_AT);
        Long cacheExpiresAt = storage.retrieveLong(KEY_CACHE_EXPIRES_AT);
        Boolean canRefresh = storage.retrieveBoolean(KEY_CAN_REFRESH);
        String keyAliasUsed = storage.retrieveString(KEY_CRYPTO_ALIAS);
        boolean emptyCredentials = isEmpty(encryptedEncoded) || cacheExpiresAt == null;

        return KEY_ALIAS.equals(keyAliasUsed) &&
                !(emptyCredentials || (hasExpired(cacheExpiresAt) || willExpire(expiresAt, minTtl)) &&
                        (canRefresh == null || !canRefresh));
    }

    private void continueGetCredentials(@Nullable String scope, final int minTtl, final BaseCallback<Credentials, CredentialsManagerException> callback) {
        String encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS);
        byte[] encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT);

        String json;
        try {
            json = new String(crypto.decrypt(encrypted));
        } catch (IncompatibleDeviceException e) {
            callback.onFailure(new CredentialsManagerException(String.format("This device is not compatible with the %s class.", SecureCredentialsManager.class.getSimpleName()), e));
            decryptCallback = null;
            return;
        } catch (CryptoException e) {
            //If keys were invalidated, existing credentials will not be recoverable.
            clearCredentials();
            callback.onFailure(new CredentialsManagerException("A change on the Lock Screen security settings have deemed the encryption keys invalid and have been recreated. " +
                    "Any previously stored content is now lost. Please, try saving the credentials again.", e));
            decryptCallback = null;
            return;
        }
        final Credentials credentials = gson.fromJson(json, Credentials.class);
        Long cacheExpiresAt = storage.retrieveLong(KEY_CACHE_EXPIRES_AT);
        Long expiresAt = credentials.getExpiresAt().getTime();
        boolean hasEmptyCredentials = isEmpty(credentials.getAccessToken()) && isEmpty(credentials.getIdToken()) || cacheExpiresAt == null;
        if (hasEmptyCredentials) {
            callback.onFailure(new CredentialsManagerException("No Credentials were previously set."));
            decryptCallback = null;
            return;
        }

        //noinspection ConstantConditions
        boolean hasEitherExpired = hasExpired(cacheExpiresAt);
        boolean willAccessTokenExpire = willExpire(expiresAt, minTtl);
        //noinspection ConstantConditions
        boolean scopeChanged = hasScopeChanged(credentials.getScope(), scope);

        if (!hasEitherExpired && !willAccessTokenExpire && !scopeChanged) {
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
        ParameterizableRequest<Credentials, AuthenticationException> request = apiClient.renewAuth(credentials.getRefreshToken());
        if (scope != null) {
            request.addParameter("scope", scope);
        }
        request.start(new AuthenticationCallback<Credentials>() {
            @Override
            public void onSuccess(@Nullable Credentials fresh) {
                long expiresAt = fresh.getExpiresAt().getTime();
                boolean willAccessTokenExpire = willExpire(expiresAt, minTtl);
                if (willAccessTokenExpire) {
                    long tokenLifetime = (expiresAt - getCurrentTimeInMillis() - minTtl * 1000) / -1000;
                    CredentialsManagerException wrongTtlException = new CredentialsManagerException(String.format("The lifetime of the renewed Access Token (%d) is less than the minTTL requested (%d). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.", tokenLifetime, minTtl));
                    callback.onFailure(wrongTtlException);
                    decryptCallback = null;
                    return;
                }

                //non-empty refresh token for refresh token rotation scenarios
                String updatedRefreshToken = isEmpty(fresh.getRefreshToken()) ? credentials.getRefreshToken() : fresh.getRefreshToken();
                Credentials refreshed = new Credentials(fresh.getIdToken(), fresh.getAccessToken(), fresh.getType(), updatedRefreshToken, fresh.getExpiresAt(), fresh.getScope());
                saveCredentials(refreshed);
                callback.onSuccess(refreshed);
                decryptCallback = null;
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
                callback.onFailure(new CredentialsManagerException("An error occurred while trying to use the Refresh Token to renew the Credentials.", error));
                decryptCallback = null;
            }
        });
    }

    @VisibleForTesting
    long getCurrentTimeInMillis() {
        return clock.getCurrentTimeMillis();
    }

    private boolean hasScopeChanged(@NonNull String storedScope, @Nullable String requiredScope) {
        if (requiredScope == null) {
            return false;
        }
        String[] stored = storedScope.split(" ");
        Arrays.sort(stored);
        String[] required = requiredScope.split(" ");
        Arrays.sort(required);
        return !Arrays.equals(stored, required);
    }

    private boolean willExpire(@Nullable Long expiresAt, long minTtl) {
        if (expiresAt == null || expiresAt <= 0) {
            //expiresAt (access token) only considered if it has a positive value, to avoid logging out users
            return false;
        }
        long nextClock = getCurrentTimeInMillis() + minTtl * 1000;
        return expiresAt <= nextClock;
    }

    private boolean hasExpired(long expiresAt) {
        return expiresAt <= getCurrentTimeInMillis();
    }

    private long calculateCacheExpiresAt(@NonNull Credentials credentials) {
        long expiresAt = credentials.getExpiresAt().getTime();

        if (credentials.getIdToken() != null) {
            JWT idToken = jwtDecoder.decode(credentials.getIdToken());
            Date idTokenExpiresAtDate = idToken.getExpiresAt();

            if (idTokenExpiresAtDate != null) {
                expiresAt = Math.min(idTokenExpiresAtDate.getTime(), expiresAt);
            }
        }
        return expiresAt;
    }

}
