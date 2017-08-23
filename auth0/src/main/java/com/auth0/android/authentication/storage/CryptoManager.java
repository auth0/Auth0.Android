package com.auth0.android.authentication.storage;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.support.annotation.VisibleForTesting;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static android.text.TextUtils.isEmpty;

@SuppressWarnings({"WeakerAccess", "unused"})
@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
public class CryptoManager {

    private static final String TAG = CryptoManager.class.getSimpleName();
    private static final int DEF_REQ_CODE = 4;

    private static final String KEY_ALIAS = CryptoManager.class.getSimpleName();
    private static final String KEY_CREDENTIALS = "com.auth0.credentials";
    private static final String KEY_EXPIRES_AT = "com.auth0.credentials_expires_at";
    private static final String KEY_CAN_REFRESH = "com.auth0.credentials_can_refresh";
    private static final String KEY_AES = "com.auth0.enc_aes";
    private static final String KEY_AES_IV = "com.auth0.enc_aes_iv";

    // Transformations encryptionAvailable for API 18 and UP
    // https://developer.android.com/training/articles/keystore.html#SupportedCiphers
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    // https://developer.android.com/reference/javax/crypto/Cipher.html
    @SuppressWarnings("SpellCheckingInspection")
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";
    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_AES = "AES";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final int RSA_MAX_INPUT_SIZE = 256;


    private final Activity activity;
    private final Storage storage;
    private final AuthenticationAPIClient apiClient;
    private final Gson gson;
    private final boolean authenticateBeforeDecrypt;

    //State for retrying operations
    private BaseCallback<Credentials, CredentialsManagerException> decryptCallback;
    private Intent authIntent;
    private int authenticationRequestCode = DEF_REQ_CODE;

    /**
     * Creates a new CryptoManager to handle Credentials
     * @param activity a valid activity context
     * @param apiClient the Auth0 Authentication API Client to handle token refreshment when needed.
     * @param storage the storage implementation to use
     *                @param requireAuthentication whether the user must authenticate using the LockScreen before accessing the credentials.
     */
    public CryptoManager(@NonNull Activity activity, @NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage, boolean requireAuthentication) {
        this.activity = activity;
        this.apiClient = apiClient;
        this.storage = storage;
        this.gson = new Gson();
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
     * @param activity a valid activity context
     * @param apiClient the Auth0 Authentication API Client to handle token refreshment when needed.
     */
    public CryptoManager(@NonNull Activity activity, @NonNull AuthenticationAPIClient apiClient) {
        this(activity, apiClient, new SharedPreferencesStorage(activity), true);
    }


    private KeyStore.PrivateKeyEntry getRSAKeyEntry() throws CredentialsManagerException {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) {
                //Return existing key
                return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
            }

            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);
            AlgorithmParameterSpec spec;
            X500Principal principal = new X500Principal("CN=Auth0.Android, O=Auth0");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                //Following code is for API 23+
                spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                        .setCertificateSubject(principal)
                        .setCertificateSerialNumber(BigInteger.ONE)
                        .setCertificateNotBefore(start.getTime())
                        .setCertificateNotAfter(end.getTime())
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .build();
            } else {
                //Following code is for API 18-22
                //Generate new RSA KeyPair and save it on the KeyStore
                KeyPairGeneratorSpec.Builder specBuilder = new KeyPairGeneratorSpec.Builder(activity)
                        .setAlias(KEY_ALIAS)
                        .setSubject(principal)
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime());
                if (authenticateBeforeDecrypt) {
                    //If a ScreenLock is setup, protect this key pair.
                    specBuilder.setEncryptionRequired();
                }
                spec = specBuilder.build();
            }

            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE);
            generator.initialize(spec);
            generator.generateKeyPair();
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
        } catch (KeyStoreException | IOException | NoSuchProviderException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | CertificateException e) {
            Log.e(TAG, "Error creating or obtaining the RSA Key Entry from the Android KeyStore.", e);
            throw new CredentialsManagerException("Error creating or obtaining the RSA Key Entry from the Android KeyStore.", e);
        } catch (UnrecoverableEntryException e) {
            //Remove and Retry
            Log.w(TAG, "RSA Key was deemed unrecoverable. Deleting the KeyEntry and recreating it.");
            deleteKeys();
            return getRSAKeyEntry();
        }
    }

    //Used to delete recreate the key pair in case of error
    private void deleteKeys() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_ALIAS);
            storage.remove(KEY_AES);
            storage.remove(KEY_AES_IV);
            clearCredentials();
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Something happened when trying to remove the RSA Key Entry from the Android KeyStore.", e);
        }
    }

    //Only used to decrypt AES key
    private byte[] RSADecrypt(byte[] encryptedInput) throws CredentialsManagerException {
        final PrivateKey privateKey = getRSAKeyEntry().getPrivateKey();
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new CredentialsManagerException("Reading the Key resulted in an error when decrypting the input.", e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            deleteKeys();
            Log.e(TAG, "Reading the Key resulted in an error when decrypting the input. Keys have been deleted.", e);
            return new byte[]{};
        }
    }

    //Only used to encrypt AES key
    private byte[] RSAEncrypt(byte[] decryptedInput) throws CredentialsManagerException {
        final Certificate certificate = getRSAKeyEntry().getCertificate();
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            return cipher.doFinal(decryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new CredentialsManagerException("Reading the Key resulted in an error when encrypting the input.", e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            deleteKeys();
            Log.e(TAG, "Reading the Key resulted in an error when encrypting the input. Keys have been deleted.", e);
            return new byte[]{};
        }
    }

    private byte[] getAESKey() throws NoSuchAlgorithmException {
        final String encodedEncryptedAES = storage.retrieveString(KEY_AES);
        if (encodedEncryptedAES != null) {
            //Return existing key
            byte[] encryptedAES = Base64.decode(encodedEncryptedAES, Base64.DEFAULT);
            return RSADecrypt(encryptedAES);
        }
        //Key doesn't exist. Generate new AES
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
        keyGen.init(RSA_MAX_INPUT_SIZE);
        byte[] aes = keyGen.generateKey().getEncoded();
        //Save encrypted encoded version
        byte[] encryptedAES = RSAEncrypt(aes);
        String encodedEncryptedAESText = new String(Base64.encode(encryptedAES, Base64.DEFAULT));
        storage.store(KEY_AES, encodedEncryptedAESText);
        return aes;
    }

    //Only used to decrypt final DATA
    private byte[] AESDecrypt(byte[] encryptedInput) throws CredentialsManagerException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            String encodedIV = storage.retrieveString(KEY_AES_IV);
            if (TextUtils.isEmpty(encodedIV)) {
                throw new IllegalArgumentException("The AES IV was never stored.");
            }
            byte[] iv = Base64.decode(encodedIV, Base64.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(encryptedInput);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            Log.e(TAG, "Error while decrypting the input.", e);
            throw new CredentialsManagerException("Error while decrypting the input.", e);
        }
    }

    //Only used to encrypt final DATA
    private byte[] AESEncrypt(byte[] decryptedInput) throws CredentialsManagerException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(decryptedInput);
            byte[] encodedIV = Base64.encode(cipher.getIV(), Base64.DEFAULT);
            //Save IV for Decrypt stage
            storage.store(KEY_AES_IV, new String(encodedIV));
            return encrypted;
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            Log.e(TAG, "Error while encrypting the input.", e);
            throw new CredentialsManagerException("Error while decrypting the input.", e);
        }
    }

    private void continueGetCredentials(final BaseCallback<Credentials, CredentialsManagerException> callback) {
        Log.e(TAG, "Trying to decrypt the stored data using the public key.");
        String encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS);
        byte[] encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT);

        String json;
        try {
            json = new String(AESDecrypt(encrypted));
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
            callback.onFailure(new CredentialsManagerException("Credentials have expired and no Refresh Token was available to renew them."));
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
            byte[] encrypted = AESEncrypt(json.getBytes());
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
