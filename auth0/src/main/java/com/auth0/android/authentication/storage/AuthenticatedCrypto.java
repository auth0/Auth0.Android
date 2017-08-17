package com.auth0.android.authentication.storage;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

@RequiresApi(Build.VERSION_CODES.M)
public class AuthenticatedCrypto {

    private static final String TAG = AuthenticatedCrypto.class.getSimpleName();
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String DEFAULT_KEY_NAME = AuthenticatedCrypto.class.getSimpleName();
    private static final int DEF_REQ_CODE = 4;
    private static final String KEY_CREDENTIALS_JSON = "credentials";
    private static final int AUTHENTICATION_WINDOW = 30;
    private final Activity activity;
    private final Gson gson;
    private final boolean available;
    private final Intent authIntent;
    private final Storage storage;

    //State for retrying operations
    private Credentials credentials;
    private boolean wasEncrypting;
    private BaseCallback<Credentials, AuthenticationException> callback;

    public AuthenticatedCrypto(@NonNull Activity activity, @NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage) {
        this.activity = activity;
        this.gson = new Gson();
        this.storage = storage;
        KeyguardManager kManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);
        this.authIntent = kManager.createConfirmDeviceCredentialIntent(null, null);
        this.available = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && kManager.isDeviceSecure();
        if (!available) {
            Log.w(TAG, "This device lacks a configured LockScreen.");
        }
    }

    public boolean checkAuthenticationResult(int requestCode, int resultCode) {
        if (requestCode != DEF_REQ_CODE) {
            //FIXME: Allow to customize the request code
            return false;
        }
        if (resultCode == Activity.RESULT_OK) {
            if (wasEncrypting) {
                saveCredentials(credentials);
            } else {
                getCredentials(callback);
            }
        }
        return true;
    }

    @SuppressLint("NewApi")
    public void saveCredentials(Credentials credentials) {
        String json = gson.toJson(credentials);
        if (!available || json == null) {
            storage.store(KEY_CREDENTIALS_JSON, json);
            return;
        }

        //noinspection TryWithIdenticalCatches
        Log.e(TAG, "Trying to encrypt the given data using the private key.");
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(DEFAULT_KEY_NAME, null);
            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            json = new String(cipher.doFinal(json.getBytes()));
            storage.store(KEY_CREDENTIALS_JSON, json);
            this.credentials = null;
        } catch (UserNotAuthenticatedException e) {
            Log.e(TAG, "User is not recently authenticated");
            this.wasEncrypting = true;
            this.credentials = credentials;
            this.activity.startActivityForResult(authIntent, DEF_REQ_CODE);
        } catch (UnrecoverableKeyException | InvalidKeyException e) {
            Log.e(TAG, "Key didn't exist. Creating one now and retrying encrypt.");
            createKey();
            saveCredentials(credentials);
        } catch (BadPaddingException | IllegalBlockSizeException | KeyStoreException | CertificateException | IOException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressLint("NewApi")
    public void getCredentials(BaseCallback<Credentials, AuthenticationException> callback) {
        String json = storage.retrieveString(KEY_CREDENTIALS_JSON);
        //FIXME: Refresh credentials when expired
        if (!available || json == null) {
            callback.onSuccess(gson.fromJson(json, Credentials.class));
            return;
        }

        Log.e(TAG, "Trying to decrypt the given data using the public key.");
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(DEFAULT_KEY_NAME, null);
            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            json = new String(cipher.doFinal());
            callback.onSuccess(gson.fromJson(json, Credentials.class));
            this.callback = null;
        } catch (UserNotAuthenticatedException e) {
            Log.e(TAG, "User is not recently authenticated");
            this.wasEncrypting = false;
            this.callback = callback;
            this.activity.startActivityForResult(authIntent, DEF_REQ_CODE);
        } catch (UnrecoverableKeyException | InvalidKeyException e) {
            Log.e(TAG, "Key didn't exist. Creating one now and retrying decrypt.");
            createKey();
            //FIXME: Doesn't make much sense to decrypt something that wasn't encrypted with the same key
            getCredentials(callback);
        } catch (BadPaddingException | IllegalBlockSizeException | KeyStoreException | CertificateException | IOException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void createKey() {
        Log.e(TAG, "Creating new key. This will replace the previous one.");
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            keyGenerator.init(new KeyGenParameterSpec.Builder(DEFAULT_KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_WINDOW)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | KeyStoreException | CertificateException | IOException e) {
            throw new RuntimeException("Failed to create a symmetric key", e);
        }
    }


}
