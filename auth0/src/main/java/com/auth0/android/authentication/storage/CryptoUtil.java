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

/**
 * Created by lbalmaceda on 8/24/17.
 * Class to handle encryption/decryption cryptographic operations using AES and RSA algorithms in devices with API 19 or higher.
 */
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

    /**
     * Attempts to recover the existing RSA Private Key entry or generates a new one as secure as
     * this device and Android version allows it if none is found.
     *
     * @return a valid RSA Private Key entry
     * @throws CryptoException             if the stored keys can't be recovered and should be deemed invalid
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required by this method
     */
    @VisibleForTesting
    KeyStore.PrivateKeyEntry getRSAKeyEntry() throws CryptoException, IncompatibleDeviceException {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) {
                //Return existing key
                return getKeyEntryCompat(keyStore);
            }

            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);
            AlgorithmParameterSpec spec;
            X500Principal principal = new X500Principal("CN=Auth0.Android,O=Auth0");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
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
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
                    //The next call can return null when the LockScreen is not configured
                    Intent authIntent = kManager.createConfirmDeviceCredentialIntent(null, null);
                    boolean keyguardEnabled = kManager.isKeyguardSecure() && authIntent != null;
                    if (keyguardEnabled) {
                        //If a ScreenLock is setup, protect this key pair.
                        specBuilder.setEncryptionRequired();
                    }
                }
                spec = specBuilder.build();
            }

            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE);
            generator.initialize(spec);
            generator.generateKeyPair();

            return getKeyEntryCompat(keyStore);
        } catch (CertificateException | InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException | KeyStoreException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - CertificateException:
             *      Thrown when certificate has expired (25 years..) or couldn't be loaded
             * - KeyStoreException:
             * - NoSuchProviderException:
             *      Thrown when "AndroidKeyStore" is not available. Was introduced on API 18.
             * - NoSuchAlgorithmException:
             *      Thrown when "RSA" algorithm is not available. Was introduced on API 18.
             * - InvalidAlgorithmParameterException:
             *      Thrown if Key Size is other than 512, 768, 1024, 2048, 3072, 4096
             *      or if Padding is other than RSA/ECB/PKCS1Padding, introduced on API 18
             *      or if Block Mode is other than ECB
             *
             * However if any of this exceptions happens to be thrown (OEMs often change their Android distribution source code),
             * all the checks performed in this class wouldn't matter and the device would not be compatible at all with it.
             *
             * Read more in https://developer.android.com/training/articles/keystore#SupportedAlgorithms
             */
            Log.e(TAG, "The device can't generate a new RSA Key pair.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IOException | UnrecoverableEntryException e) {
            /*
             * Any of this exceptions mean the old key pair is somehow corrupted.
             * We can delete it and let the user retry the operation.
             *
             * - IOException:
             *      Thrown when there is an I/O or format problem with the keystore data.
             * - UnrecoverableEntryException:
             *      Thrown when the key cannot be recovered. Probably because it was invalidated by a Lock Screen change.
             */
            deleteKeys();
            throw new CryptoException("The existing RSA key pair could not be recovered and has been deleted. " +
                    "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", e);
        }
    }

    /**
     * Helper method compatible with older Android versions to load the Private Key Entry from
     * the KeyStore using the {@link #KEY_ALIAS}.
     *
     * @param keyStore the KeyStore instance. Must be initialized (loaded).
     * @return the key entry stored in the KeyStore.
     * @throws KeyStoreException           if the keystore was not initialized.
     * @throws NoSuchAlgorithmException    if device is not compatible with RSA algorithm. RSA is available since API 18.
     * @throws UnrecoverableEntryException if key cannot be recovered. Probably because it was invalidated by a Lock Screen change.
     */
    private KeyStore.PrivateKeyEntry getKeyEntryCompat(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
        }

        //Following code is for API 28+
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

        if (privateKey == null) {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
        }

        Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
        return new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate});
    }

    /**
     * Removes the AES and RSA keys generated in a previous execution.
     * Used when we want the next call to {@link #encrypt(byte[])} or {@link #decrypt(byte[])}
     * to recreate the keys.
     */
    private void deleteKeys() {
        storage.remove(KEY_ALIAS);
        storage.remove(KEY_IV_ALIAS);
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_ALIAS);
            Log.d(TAG, "Deleting the existing RSA key pair from the KeyStore.");
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to remove the RSA KeyEntry from the Android KeyStore.", e);
        }
    }

    /**
     * Decrypts the given input using a generated RSA Private Key.
     * Used to decrypt the AES key for later usage.
     *
     * @param encryptedInput the input bytes to decrypt
     * @return the decrypted bytes output
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    @VisibleForTesting
    byte[] RSADecrypt(byte[] encryptedInput) throws IncompatibleDeviceException {
        try {
            PrivateKey privateKey = getRSAKeyEntry().getPrivateKey();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedInput);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if PKCS1Padding is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             * - IllegalBlockSizeException:
             *      Thrown only on encrypt mode.
             * - BadPaddingException:
             *      Thrown if the input doesn't contain the proper padding bytes.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "The device can't decrypt input using a RSA Key.", e);
            throw new IncompatibleDeviceException(e);
        }
    }

    /**
     * Encrypts the given input using a generated RSA Public Key.
     * Used to encrypt the AES key for later storage.
     *
     * @param decryptedInput the input bytes to encrypt
     * @return the encrypted bytes output
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    @VisibleForTesting
    byte[] RSAEncrypt(byte[] decryptedInput) throws IncompatibleDeviceException {
        try {
            Certificate certificate = getRSAKeyEntry().getCertificate();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            return cipher.doFinal(decryptedInput);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if PKCS1Padding is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             * - IllegalBlockSizeException:
             *      Thrown if no padding has been requested and the length is not multiple of block size.
             * - BadPaddingException:
             *      Thrown only on decrypt mode.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "The device can't encrypt input using a RSA Key.", e);
            throw new IncompatibleDeviceException(e);
        }
    }

    /**
     * Attempts to recover the existing AES Key or generates a new one if none is found.
     *
     * @return a valid  AES Key bytes
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    @VisibleForTesting
    byte[] getAESKey() throws IncompatibleDeviceException {
        final String encodedEncryptedAES = storage.retrieveString(KEY_ALIAS);
        if (encodedEncryptedAES != null) {
            //Return existing key
            byte[] encryptedAES = Base64.decode(encodedEncryptedAES, Base64.DEFAULT);
            return RSADecrypt(encryptedAES);
        }
        //Key doesn't exist. Generate new AES
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGen.init(AES_KEY_SIZE);
            byte[] aes = keyGen.generateKey().getEncoded();
            //Save encrypted encoded version
            byte[] encryptedAES = RSAEncrypt(aes);
            String encodedEncryptedAESText = new String(Base64.encode(encryptedAES, Base64.DEFAULT));
            storage.store(KEY_ALIAS, encodedEncryptedAESText);
            return aes;
        } catch (NoSuchAlgorithmException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchAlgorithmException:
             *      Thrown if the Algorithm implementation is not available. AES was introduced in API 1
             *
             * However if any of this exceptions happens to be thrown (OEMs often change their Android distribution source code),
             * all the checks performed in this class wouldn't matter and the device would not be compatible at all with it.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/KeyGenerator
             */
            Log.e(TAG, "Error while creating the AES key.", e);
            throw new IncompatibleDeviceException(e);
        }
    }


    /**
     * Encrypts the given input bytes using a symmetric key (AES).
     * The AES key is stored protected by an asymmetric key pair (RSA).
     *
     * @param encryptedInput the input bytes to decrypt. There's no limit in size.
     * @return the decrypted output bytes
     * @throws CryptoException             if the RSA Key pair was deemed invalid and got deleted. Operation can be retried.
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    public byte[] decrypt(byte[] encryptedInput) throws CryptoException, IncompatibleDeviceException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            String encodedIV = storage.retrieveString(KEY_IV_ALIAS);
            if (TextUtils.isEmpty(encodedIV)) {
                //AES key was JUST generated. If anything existed before, should be encrypted again first.
                throw new CryptoException("The encryption keys changed recently. You need to re-encrypt something first.", null);
            }
            byte[] iv = Base64.decode(encodedIV, Base64.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(encryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if NOPADDING is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             * - InvalidAlgorithmParameterException:
             *      If the IV parameter is null.
             * - BadPaddingException:
             *      Thrown if the input doesn't contain the proper padding bytes. In this case, if the input contains padding.
             * - IllegalBlockSizeException:
             *      Thrown only on encrypt mode.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "Error while decrypting the input.", e);
            throw new IncompatibleDeviceException(e);
        }
    }

    /**
     * Encrypts the given input bytes using a symmetric key (AES).
     * The AES key is stored protected by an asymmetric key pair (RSA).
     *
     * @param decryptedInput the input bytes to encrypt. There's no limit in size.
     * @return the encrypted output bytes
     * @throws CryptoException             if the RSA Key pair was deemed invalid and got deleted. Operation can be retried.
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    public byte[] encrypt(byte[] decryptedInput) throws CryptoException, IncompatibleDeviceException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(decryptedInput);
            byte[] encodedIV = Base64.encode(cipher.getIV(), Base64.DEFAULT);
            //Save IV for Decrypt stage
            storage.store(KEY_IV_ALIAS, new String(encodedIV));
            return encrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            /*
             * This exceptions are safe to be ignored:
             *
             * - NoSuchPaddingException:
             *      Thrown if NOPADDING is not available. Was introduced in API 1.
             * - NoSuchAlgorithmException:
             *      Thrown if the transformation is null, empty or invalid, or if no security provider
             *      implements it. Was introduced in API 1.
             * - InvalidKeyException:
             *      Thrown if the given key is inappropriate for initializing this cipher.
             * - InvalidAlgorithmParameterException:
             *      If the IV parameter is null.
             * - BadPaddingException:
             *      Thrown only on decrypt mode.
             * - IllegalBlockSizeException:
             *      Thrown if no padding has been requested and the length is not multiple of block size.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "Error while encrypting the input.", e);
            throw new IncompatibleDeviceException(e);
        }
    }

}
