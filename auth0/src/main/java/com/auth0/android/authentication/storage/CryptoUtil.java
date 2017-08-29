package com.auth0.android.authentication.storage;

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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
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

/**
 * Created by lbalmaceda on 8/24/17.
 */
//19 and up
@SuppressWarnings("WeakerAccess")
@RequiresApi(api = Build.VERSION_CODES.KITKAT)
class CryptoUtil {

    private static final String TAG = CryptoUtil.class.getSimpleName();

    // Transformations available since API 18
    // https://developer.android.com/training/articles/keystore.html#SupportedCiphers
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    // https://developer.android.com/reference/javax/crypto/Cipher.html
    @SuppressWarnings("SpellCheckingInspection")
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_AES = "AES";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;

    private final String KEY_ALIAS;
    private final String KEY_IV_ALIAS;
    private final Storage storage;
    private final Context context;

    public CryptoUtil(@NonNull Context context, @NonNull Storage storage, @NonNull String keyAlias) {
        keyAlias = keyAlias.trim();
        if (TextUtils.isEmpty(keyAlias)) {
            throw new IllegalArgumentException("RSA and AES Key alias must be valid.");
        }
        this.KEY_ALIAS = keyAlias;
        this.KEY_IV_ALIAS = keyAlias + "_iv";
        this.context = context;
        this.storage = storage;
    }

    @VisibleForTesting
    KeyStore.PrivateKeyEntry getRSAKeyEntry() throws KeyException {
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
            X500Principal principal = new X500Principal("CN=Auth0.Android,O=Auth0");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                //Following code is for API 23+
                spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                        .setCertificateSubject(principal)
                        .setCertificateSerialNumber(BigInteger.ONE)
                        .setCertificateNotBefore(start.getTime())
                        .setCertificateNotAfter(end.getTime())
                        .setKeySize(RSA_KEY_SIZE)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .build();
            } else {
                //Following code is for API 18-22
                //Generate new RSA KeyPair and save it on the KeyStore
                KeyPairGeneratorSpec.Builder specBuilder = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(KEY_ALIAS)
                        .setSubject(principal)
                        .setKeySize(RSA_KEY_SIZE)
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime());

                KeyguardManager kManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
                Intent authIntent = null;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
                    //The next call can return null when the LockScreen is not configured
                    authIntent = kManager.createConfirmDeviceCredentialIntent(null, null);
                }
                boolean keyguardEnabled = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && kManager.isKeyguardSecure() && authIntent != null;
                if (keyguardEnabled) {
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
            Log.e(TAG, "An error occurred while trying to obtain the RSA Key Entry from the Android KeyStore.", e);
            throw new KeyException("An error occurred while trying to obtain the RSA KeyPair Entry from the Android KeyStore.", e);
        } catch (UnrecoverableEntryException e) {
            //Remove keys and Retry
            Log.w(TAG, "RSA KeyPair was deemed unrecoverable. Deleting the existing entry and trying again.");
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
            storage.remove(KEY_ALIAS);
            storage.remove(KEY_IV_ALIAS);
            //FIXME: After a call to this method it should clear the credentials from the storage
//            clearCredentials();
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to remove the RSA KeyEntry from the Android KeyStore.", e);
        }
    }

    //Only used to decrypt AES key
    @VisibleForTesting
    byte[] RSADecrypt(byte[] encryptedInput) throws CryptoException {
        try {
            PrivateKey privateKey = getRSAKeyEntry().getPrivateKey();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | KeyException e) {
            throw new CryptoException("Couldn't decrypt the input using the RSA Key.", e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            deleteKeys();
            Log.e(TAG, "The input contained unexpected content, probably because it was encrypted using a different key. " +
                    "The existing keys have been deleted and a new pair will be created next time. Please try to encrypt the content again.", e);
            return new byte[]{};
        }
    }

    //Only used to encrypt AES key
    @VisibleForTesting
    byte[] RSAEncrypt(byte[] decryptedInput) throws CryptoException {
        try {
            Certificate certificate = getRSAKeyEntry().getCertificate();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            return cipher.doFinal(decryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | KeyException e) {
            throw new CryptoException("Couldn't encrypt the input using the RSA Key.", e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            deleteKeys();
            Log.e(TAG, "The input contained unexpected content and it was deemed unrecoverable." +
                    " The existing keys have been deleted and a new pair will be created next time.", e);
            return new byte[]{};
        }
    }

    @VisibleForTesting
    byte[] getAESKey() throws KeyException {
        final String encodedEncryptedAES = storage.retrieveString(KEY_ALIAS);
        if (encodedEncryptedAES != null) {
            //Return existing key
            byte[] encryptedAES = Base64.decode(encodedEncryptedAES, Base64.DEFAULT);
            return RSADecrypt(encryptedAES);
        }
        //Key doesn't exist. Generate new AES
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES, ANDROID_KEY_STORE);
            keyGen.init(AES_KEY_SIZE);
            byte[] aes = keyGen.generateKey().getEncoded();
            //Save encrypted encoded version
            byte[] encryptedAES = RSAEncrypt(aes);
            String encodedEncryptedAESText = new String(Base64.encode(encryptedAES, Base64.DEFAULT));
            storage.store(KEY_ALIAS, encodedEncryptedAESText);
            return aes;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            Log.e(TAG, "Error while creating the AES key.", e);
            throw new KeyException("Error while creating the AES key.", e);
        }
    }

    //Only used to decrypt final DATA
    public byte[] decrypt(byte[] encryptedInput) throws CryptoException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            String encodedIV = storage.retrieveString(KEY_IV_ALIAS);
            if (TextUtils.isEmpty(encodedIV)) {
                throw new InvalidAlgorithmParameterException("The AES Key exists but an IV was never stored. Try to encrypt something first.");
            }
            byte[] iv = Base64.decode(encodedIV, Base64.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(encryptedInput);
        } catch (KeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | BadPaddingException | NoSuchPaddingException | IllegalBlockSizeException e) {
            Log.e(TAG, "Error while decrypting the input.", e);
            throw new CryptoException("Error while decrypting the input.", e);
        }
    }

    //Only used to encrypt final DATA
    public byte[] encrypt(byte[] decryptedInput) throws CryptoException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(decryptedInput);
            byte[] encodedIV = Base64.encode(cipher.getIV(), Base64.DEFAULT);
            //Save IV for Decrypt stage
            storage.store(KEY_IV_ALIAS, new String(encodedIV));
            return encrypted;
        } catch (KeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            Log.e(TAG, "Error while encrypting the input.", e);
            throw new CryptoException("Error while encrypting the input.", e);
        }
    }

}
