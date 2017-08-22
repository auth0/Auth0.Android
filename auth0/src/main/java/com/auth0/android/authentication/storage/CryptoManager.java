package com.auth0.samples;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.storage.CredentialsManagerException;
import com.auth0.android.authentication.storage.Storage;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.result.Credentials;
import com.google.gson.Gson;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class CryptoManager {

    private static final String TAG = CryptoManager.class.getSimpleName();
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = CryptoManager.class.getSimpleName();
    private static final int DEF_REQ_CODE = 4;
    private static final String KEY_CREDENTIALS = "credentials";
    private static final String KEY_AES_KEY = "aes";
    private static final String KEY_AES_IV = "aes_iv";
    private static final int MAX_RSA_INPUT_SIZE_BYTES = 256;

    // Transformations available for API 18 and UP
    // https://developer.android.com/training/articles/keystore.html#SupportedCiphers
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";

    private static final int AUTHENTICATION_WINDOW = 30;


    private final Activity activity;
    private final Gson gson;
    private final boolean available;
    //    private final Intent authIntent;
    private final Storage storage;

    //State for retrying operations
    private Credentials credentials;
    private boolean wasEncrypting;
    private BaseCallback<Void, CredentialsManagerException> encryptCallback;
    private BaseCallback<Credentials, CredentialsManagerException> decryptCallback;

    public CryptoManager(@NonNull Activity activity, @NonNull AuthenticationAPIClient apiClient, @NonNull Storage storage) {
        this.activity = activity;
        this.gson = new Gson();
        this.storage = storage;
        KeyguardManager kManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);
//        this.authIntent = kManager.createConfirmDeviceCredentialIntent(null, null);
        this.available = Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2 && kManager.isKeyguardSecure();
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
                saveCredentials(credentials, encryptCallback);
            } else {
                getCredentials(decryptCallback);
            }
        }
        return true;
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private KeyStore.PrivateKeyEntry getRSAKeyEntry() throws RuntimeException {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) {
                //Return existing key
                return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
            }

            //Generate new RSA KeyPair and save it on the KeyStore
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(activity)
                    .setAlias(KEY_ALIAS)
                    .setSubject(new X500Principal("CN=Auth0.Android, O=Auth0"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE);
            generator.initialize(spec);
            generator.generateKeyPair();
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
        } catch (Exception e) {
            Log.e(TAG, "Error creating/obtaining AndroidKeyStore key", e);
            throw new RuntimeException("Error creating/obtaining AndroidKeyStore key", e);
        }
    }

    //Only used to decrypt AES key
    private byte[] RSADecrypt(byte[] encryptedInput) {
        final PrivateKey privateKey = getRSAKeyEntry().getPrivateKey();
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedInput);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    //Only used to encrypt AES key
    private byte[] RSAEncrypt(byte[] decryptedInput) {
        final Certificate certificate = getRSAKeyEntry().getCertificate();
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            return cipher.doFinal(decryptedInput);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private byte[] getAESKey() throws NoSuchAlgorithmException {
        final String encodedEncryptedAES = storage.retrieveString(KEY_AES_KEY);
        if (encodedEncryptedAES != null) {
            //Return existing key
            byte[] encryptedAES = Base64.decode(encodedEncryptedAES, Base64.DEFAULT);
            return RSADecrypt(encryptedAES);
        }
        //Key doesn't exist. Generate new AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(MAX_RSA_INPUT_SIZE_BYTES);
        byte[] aes = keyGen.generateKey().getEncoded();
        //Save encrypted encoded version
        final byte[] encryptedAES = RSAEncrypt(aes);
        String encodedEncryptedAESText = new String(Base64.encode(encryptedAES, Base64.DEFAULT));
        storage.store(KEY_AES_KEY, encodedEncryptedAESText);
        return aes;
    }

    //Only used to decrypt final DATA
    private byte[] AESDecrypt(byte[] encryptedInput) {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), "AES");
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            String encodedIV = storage.retrieveString(KEY_AES_IV);
            if (TextUtils.isEmpty(encodedIV)) {
                throw new IllegalArgumentException("The IV was never stored.");
            }
            byte[] iv = Base64.decode(encodedIV, Base64.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(encryptedInput);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    //Only used to encrypt final DATA
    private byte[] AESEncrypt(byte[] decryptedInput) {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), "AES");
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            final byte[] encrypted = cipher.doFinal(decryptedInput);
            final byte[] encodedIV = Base64.encode(cipher.getIV(), Base64.DEFAULT);
            //Save IV for next Decrypt step
            storage.store(KEY_AES_IV, new String(encodedIV));
            return encrypted;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


    @SuppressLint("NewApi")
    public void saveCredentials(Credentials credentials, BaseCallback<Void, CredentialsManagerException> callback) {
        String json = gson.toJson(credentials);
        if (!available || json == null) {
            storage.store(KEY_CREDENTIALS, json);
            callback.onSuccess(null);
            return;
        }

        Log.e(TAG, "Trying to encrypt the given data using the private key.");
        try {
            final byte[] encrypted = AESEncrypt(json.getBytes());
            String encryptedEncoded = Base64.encodeToString(encrypted, Base64.DEFAULT);
            storage.store(KEY_CREDENTIALS, encryptedEncoded);
            callback.onSuccess(null);
        } catch (Exception e) {
            callback.onFailure(new CredentialsManagerException("Couldn't encrypt the credentials", e));
        }
    }

    @SuppressLint("NewApi")
    public void getCredentials(BaseCallback<Credentials, CredentialsManagerException> callback) {
        String encryptedEncoded = storage.retrieveString(KEY_CREDENTIALS);
        //FIXME: Refresh credentials when expired
        if (!available || encryptedEncoded == null) {
            callback.onSuccess(gson.fromJson(encryptedEncoded, Credentials.class));
            return;
        }

        //FIXME: If was not available but now it is, data should be re-encrypted or it will fail
        Log.e(TAG, "Trying to decrypt the given data using the public key.");
        try {
            byte[] encrypted = Base64.decode(encryptedEncoded, Base64.DEFAULT);
            String json = new String(AESDecrypt(encrypted));
            callback.onSuccess(gson.fromJson(json, Credentials.class));
        } catch (Exception e) {
            callback.onFailure(new CredentialsManagerException("Couldn't encrypt the credentials", e));
        }
    }

}
