package com.auth0.android.authentication.storage;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
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
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import java.security.spec.MGF1ParameterSpec;

/**
 * Created by lbalmaceda on 8/24/17.
 * Class to handle encryption/decryption cryptographic operations using AES and RSA algorithms in devices with API 19 or higher.
 */
@SuppressWarnings("WeakerAccess")
class CryptoUtil {

    private static final String TAG = CryptoUtil.class.getSimpleName();

    // Transformations available since API 18
    // https://developer.android.com/training/articles/keystore.html#SupportedCiphers
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    /**
     * !!! WARNING !!!
     * "RSA/ECB/PKCS1Padding" is cryptographically deprecated due to vulnerabilities
     * (e.g. Bleichenbacher padding oracle attacks) and MUST NOT be used for encrypting
     * new data or for any general-purpose RSA operations.
     * 
     * This transformation exists solely to DECRYPT pre-existing legacy data that was
     * originally encrypted with PKCS#1 v1.5 padding, so that it can be re-encrypted
     * using the secure OAEP-based {@link #RSA_TRANSFORMATION}. Once all legacy data has
     * been migrated, support for this constant and any code paths that use it should be
     * removed.
     */
    // CodeQL suppression: This legacy constant is required for backward compatibility
    // to decrypt credentials encrypted with PKCS1 before the migration to OAEP.
    // It is only used for decryption (reading old data), never encryption (writing new data).
    // This constant will be removed once all users have migrated to OAEP.
    @SuppressWarnings("java/rsa-without-oaep")
    private static final String LEGACY_PKCS1_RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    // https://developer.android.com/reference/javax/crypto/Cipher.html
    @SuppressWarnings("SpellCheckingInspection")
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_AES = "AES";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;

    // Explicit OAEP specification for consistent behavior across JCE providers.
    // Using SHA-1 for both OAEP hash and MGF1 hash as it's well-supported by Android KeyStore.
    // Note: SHA-1 in OAEP/MGF1 context only requires preimage resistance (still secure),
    // unlike digital signatures which require collision resistance.
    private static final OAEPParameterSpec OAEP_SPEC = new OAEPParameterSpec(
        "SHA-1",
        "MGF1",
        MGF1ParameterSpec.SHA1,
        PSource.PSpecified.DEFAULT
    );

    private static final byte FORMAT_MARKER = 0x01;

    private static final int GCM_TAG_LENGTH = 16;
    private static final int MIN_DATA_LENGTH = 1;
    private static final int FORMAT_HEADER_LENGTH = 2;

    private final String OLD_KEY_ALIAS;
    private final String OLD_KEY_IV_ALIAS;
    private final String KEY_ALIAS;
    private final String KEY_IV_ALIAS;
    private final Storage storage;
    private final Context context;

    public CryptoUtil(@NonNull Context context, @NonNull Storage storage, @NonNull String keyAlias) {
        keyAlias = keyAlias.trim();
        if (TextUtils.isEmpty(keyAlias)) {
            throw new IllegalArgumentException("RSA and AES Key alias must be valid.");
        }
        String iv_suffix = "_iv";
        this.OLD_KEY_ALIAS = keyAlias;
        this.OLD_KEY_IV_ALIAS = keyAlias + iv_suffix;
        this.KEY_ALIAS = context.getPackageName() + "." + keyAlias;
        this.KEY_IV_ALIAS = context.getPackageName() + "." + keyAlias + iv_suffix;
        this.context = context;
        this.storage = storage;
    }

    /**
     * Decrypts data that was encrypted using legacy RSA/PKCS1 padding.
     * <p>
     * WARNING: This must only be used for decrypting legacy data during migration.
     * New code must always use OAEP padding for RSA encryption/decryption.
     * 
     * @param encryptedData The data encrypted with PKCS1 padding
     * @param privateKey The private key for decryption
     * @return The decrypted data
     * @throws NoSuchPaddingException If PKCS1 padding is not available
     * @throws NoSuchAlgorithmException If RSA algorithm is not available
     * @throws InvalidKeyException If the private key is invalid
     * @throws BadPaddingException If the encrypted data has invalid padding
     * @throws IllegalBlockSizeException If the encrypted data size is invalid
     */
    @NonNull
    @SuppressWarnings("java/rsa-without-oaep")
    private static byte[] RSADecryptLegacyPKCS1(@NonNull byte[] encryptedData,
                                                 @NonNull PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher rsaPkcs1Cipher = Cipher.getInstance(LEGACY_PKCS1_RSA_TRANSFORMATION);
        rsaPkcs1Cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaPkcs1Cipher.doFinal(encryptedData);
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
            if (keyStore.containsAlias(OLD_KEY_ALIAS)) {
                //Return existing key. On weird cases, the alias would be present but the key not
                KeyStore.PrivateKeyEntry existingKey = getKeyEntryCompat(keyStore, OLD_KEY_ALIAS);
                if (existingKey != null) {
                    return existingKey;
                }
            } else if (keyStore.containsAlias(KEY_ALIAS)) {
                KeyStore.PrivateKeyEntry existingKey = getKeyEntryCompat(keyStore, KEY_ALIAS);
                if (existingKey != null) {
                    return existingKey;
                }
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
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256)
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

            return getKeyEntryCompat(keyStore, KEY_ALIAS);
        } catch (CertificateException | InvalidAlgorithmParameterException |
                 NoSuchProviderException | NoSuchAlgorithmException | KeyStoreException |
                 ProviderException e) {
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
             * - ProviderException:
             *      Thrown on some modified devices when KeyPairGenerator#generateKeyPair is called.
             *      See: https://www.bountysource.com/issues/45527093-keystore-issues
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
             * We can delete both the RSA and the AES keys and let the user retry the operation.
             *
             * - IOException:
             *      Thrown when there is an I/O or format problem with the keystore data.
             * - UnrecoverableEntryException:
             *      Thrown when the key cannot be recovered. Probably because it was invalidated by a Lock Screen change.
             */
            deleteRSAKeys();
            deleteAESKeys();
            throw new CryptoException("The existing RSA key pair could not be recovered and has been deleted. " +
                    "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", e);
        }
    }

    /**
     * Helper method compatible with older Android versions to load the Private Key Entry from
     * the KeyStore using the {@link #KEY_ALIAS}.
     *
     * @param keyStore the KeyStore instance. Must be initialized (loaded).
     * @return the key entry stored in the KeyStore or null if not present.
     * @throws KeyStoreException           if the keystore was not initialized.
     * @throws NoSuchAlgorithmException    if device is not compatible with RSA algorithm. RSA is available since API 18.
     * @throws UnrecoverableEntryException if key cannot be recovered. Probably because it was invalidated by a Lock Screen change.
     */
    private KeyStore.PrivateKeyEntry getKeyEntryCompat(KeyStore keyStore, String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        }

        //Following code is for API 28+
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

        if (privateKey == null) {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        }

        Certificate certificate = keyStore.getCertificate(alias);
        if (certificate == null) {
            return null;
        }
        return new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate});
    }

    /**
     * Removes the RSA keys generated in a previous execution.
     * Used when we want the next call to {@link #encrypt(byte[])} or {@link #decrypt(byte[])}
     * to recreate the keys.
     */
    private void deleteRSAKeys() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_ALIAS);
            keyStore.deleteEntry(OLD_KEY_ALIAS);
            Log.d(TAG, "Deleting the existing RSA key pair from the KeyStore.");
        } catch (KeyStoreException | CertificateException | IOException |
                 NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to remove the RSA KeyEntry from the Android KeyStore.", e);
        }
    }

    /**
     * Removes the AES keys generated in a previous execution.
     * Used when we want the next call to {@link #encrypt(byte[])} or {@link #decrypt(byte[])}
     * to recreate the keys.
     */
    private void deleteAESKeys() {
        storage.remove(KEY_ALIAS);
        storage.remove(KEY_IV_ALIAS);
        storage.remove(OLD_KEY_ALIAS);
        storage.remove(OLD_KEY_IV_ALIAS);
    }

    /**
     * Decrypts the given input using a generated RSA Private Key.
     * Used to decrypt the AES key for later usage.
     *
     * @param encryptedInput the input bytes to decrypt
     * @return the decrypted bytes output
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     * @throws CryptoException             if the stored RSA keys can't be recovered and should be deemed invalid
     */
    @VisibleForTesting
    byte[] RSADecrypt(byte[] encryptedInput) throws IncompatibleDeviceException, CryptoException {
        try {
            PrivateKey privateKey = getRSAKeyEntry().getPrivateKey();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SPEC);
            return cipher.doFinal(encryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | ProviderException e) {
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
             * - InvalidAlgorithmParameterException:
             *      Thrown if the OAEP parameters are invalid or unsupported.
             * - ProviderException:
             *      Thrown on Android 12+ (Keystore2) when the key's padding restriction is
             *      incompatible with the cipher transformation (e.g. a PKCS1-restricted key
             *      initialised with an OAEP spec). On Android < 12 this surfaces as
             *      InvalidKeyException instead.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "The device can't decrypt input using a RSA Key.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IllegalArgumentException | IllegalBlockSizeException | BadPaddingException e) {
            /*
             * Any of this exceptions mean the encrypted input is somehow corrupted and cannot be recovered.
             * Delete the AES keys since those originated the input.
             *
             * - IllegalBlockSizeException:
             *      Thrown only on encrypt mode.
             * - BadPaddingException:
             *      Thrown if the input doesn't contain the proper padding bytes.
             * - IllegalArgumentException
             *      Thrown when doFinal is called with a null input.
             */
            deleteAESKeys();
            throw new CryptoException("The RSA encrypted input is corrupted and cannot be recovered. Please discard it.", e);
        }
    }

    /**
     * Encrypts the given input using a generated RSA Public Key.
     * Used to encrypt the AES key for later storage.
     *
     * @param decryptedInput the input bytes to encrypt
     * @return the encrypted bytes output
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     * @throws CryptoException             if the stored RSA keys can't be recovered and should be deemed invalid
     */
    @VisibleForTesting
    byte[] RSAEncrypt(byte[] decryptedInput) throws IncompatibleDeviceException, CryptoException {
        try {
            Certificate certificate = getRSAKeyEntry().getCertificate();
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey(), OAEP_SPEC);
            return cipher.doFinal(decryptedInput);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | ProviderException e) {
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
             * - InvalidAlgorithmParameterException:
             *      Thrown if the OAEP parameters are invalid or unsupported.
             * - ProviderException:
             *      Thrown on Android 12+ (Keystore2) when the key's padding restriction is
             *      incompatible with the cipher transformation (e.g. a PKCS1-restricted key
             *      initialised with an OAEP spec). On Android < 12 this surfaces as
             *      InvalidKeyException instead.
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "The device can't encrypt input using a RSA Key.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            /*
             * They really should not be thrown at all since padding is requested in the transformation.
             * Delete the AES keys since those originated the input.
             *
             * - IllegalBlockSizeException:
             *      Thrown if no padding has been requested and the length is not multiple of block size.
             * - BadPaddingException:
             *      Thrown only on decrypt mode.
             */
            deleteAESKeys();
            throw new CryptoException("The RSA decrypted input is invalid.", e);
        }
    }

    /**
     * Attempts to migrate legacy PKCS1-encrypted AES key to OAEP format.
     * This method tries to decrypt the AES key using legacy PKCS1 padding,
     * then re-encrypts it with OAEP and stores it for future use.
     *
     * @param encryptedAESBytes the encrypted AES key bytes
     * @return the decrypted AES key if migration succeeds, or null if migration fails
     */
    @Nullable
    private byte[] attemptPKCS1Migration(byte[] encryptedAESBytes) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            KeyStore.PrivateKeyEntry rsaKey = findRSAKeyEntry(keyStore);
            if (rsaKey == null) {
                Log.d(TAG, "No RSA key found for migration");
                return null;
            }

            byte[] decryptedAESKey = RSADecryptLegacyPKCS1(encryptedAESBytes, rsaKey.getPrivateKey());

            if (!isValidAESKeyLength(decryptedAESKey)) {
                Log.e(TAG, "Decrypted AES key has invalid length: " + decryptedAESKey.length);
                return null;
            }

            Log.d(TAG, "PKCS1 migration successful - deleting old keys");
            
            deleteRSAKeys();

            byte[] encryptedAESWithOAEP = RSAEncrypt(decryptedAESKey);
            String encodedEncryptedAES = new String(Base64.encode(encryptedAESWithOAEP, Base64.DEFAULT), StandardCharsets.UTF_8);
            storage.store(KEY_ALIAS, encodedEncryptedAES);
            
            Log.d(TAG, "AES key re-encrypted with OAEP and stored");
            return decryptedAESKey;

        } catch (BadPaddingException | IllegalBlockSizeException e) {
            Log.e(TAG, "PKCS1 decryption failed. Data may be corrupted.", e);
        } catch (KeyStoreException | CertificateException | IOException | 
                 NoSuchAlgorithmException | UnrecoverableEntryException |
                 NoSuchPaddingException | InvalidKeyException e) {
            Log.e(TAG, "Migration failed due to key access error.", e);
        } catch (CryptoException e) {
            Log.e(TAG, "Failed to re-encrypt AES key with OAEP.", e);
        }
        return null;
    }

    /**
     * Finds the RSA private key entry from KeyStore, checking both current and legacy aliases.
     *
     * @param keyStore the initialized KeyStore instance
     * @return the RSA key entry, or null if not found
     */
    @Nullable
    private KeyStore.PrivateKeyEntry findRSAKeyEntry(KeyStore keyStore) 
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return getKeyEntryCompat(keyStore, KEY_ALIAS);
        } else if (keyStore.containsAlias(OLD_KEY_ALIAS)) {
            return getKeyEntryCompat(keyStore, OLD_KEY_ALIAS);
        }
        return null;
    }

    /**
     * Validates that the decrypted AES key has the correct length for AES-256.
     *
     * @param aesKey the decrypted AES key bytes
     * @return true if the key is valid (32 bytes), false otherwise
     */
    private boolean isValidAESKeyLength(byte[] aesKey) {
        return aesKey != null && aesKey.length == AES_KEY_SIZE / 8;
    }

    /**
     * Attempts to recover the existing AES Key or generates a new one if none is found.
     *
     * @return a valid  AES Key bytes
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     * @throws CryptoException             if the stored RSA keys can't be recovered and should be deemed invalid
     */
    @VisibleForTesting
    byte[] getAESKey() throws IncompatibleDeviceException, CryptoException {
        // Step 1: Try to recover existing AES key encrypted with current format (OAEP)
        byte[] aesKey = tryRecoverCurrentAESKey();
        if (aesKey != null) {
            return aesKey;
        }

        // Step 2: Try to migrate legacy AES key stored at OLD_KEY_ALIAS
        aesKey = tryMigrateLegacyAESKey();
        if (aesKey != null) {
            return aesKey;
        }

        // Step 3: Generate new AES key
        return generateNewAESKey();
    }

    /**
     * Attempts to recover the AES key stored at KEY_ALIAS using OAEP decryption.
     * If OAEP fails, attempts PKCS1 decryption for legacy data migration.
     *
     * @return the decrypted AES key, or null if no key exists or recovery failed
     * @throws IncompatibleDeviceException if the device doesn't support required crypto operations
     *         and migration also fails
     */
    @Nullable
    private byte[] tryRecoverCurrentAESKey() throws IncompatibleDeviceException {
        String encodedEncryptedAES = storage.retrieveString(KEY_ALIAS);
        if (TextUtils.isEmpty(encodedEncryptedAES)) {
            return null;
        }

        byte[] encryptedAESBytes = Base64.decode(encodedEncryptedAES, Base64.DEFAULT);
        CryptoException oaepException = null;

        try {
            return RSADecrypt(encryptedAESBytes);
        } catch (CryptoException e) {
            // OAEP decryption failed - could be legacy PKCS1 data or device incompatibility
            // Store exception to re-throw if migration also fails
            oaepException = e;
            Log.d(TAG, "OAEP decryption failed, attempting PKCS1 migration", e);
        }

        // OAEP failed - attempt PKCS1 migration
        byte[] migratedKey = attemptPKCS1Migration(encryptedAESBytes);
        if (migratedKey != null) {
            return migratedKey;
        }

        // Migration failed or wasn't attempted
        // If the original error was IncompatibleDeviceException, re-throw it
        if (oaepException instanceof IncompatibleDeviceException) {
            throw (IncompatibleDeviceException) oaepException;
        }

        // Recovery failed - clean up corrupted keys
        Log.w(TAG, "Could not recover AES key. Deleting corrupted keys.");
        deleteRSAKeys();
        deleteAESKeys();
        return null;
    }

    /**
     * Attempts to migrate a legacy AES key stored at OLD_KEY_ALIAS.
     * Decrypts with PKCS1, re-encrypts with OAEP, and stores at KEY_ALIAS.
     *
     * @return the decrypted AES key if migration succeeds, or null otherwise
     */
    @Nullable
    private byte[] tryMigrateLegacyAESKey() {
        String encodedOldAES = storage.retrieveString(OLD_KEY_ALIAS);
        if (TextUtils.isEmpty(encodedOldAES)) {
            return null;
        }

        try {
            byte[] encryptedOldAESBytes = Base64.decode(encodedOldAES, Base64.DEFAULT);
            KeyStore.PrivateKeyEntry rsaKeyEntry = getRSAKeyEntry();

            byte[] decryptedAESKey = RSADecryptLegacyPKCS1(encryptedOldAESBytes, rsaKeyEntry.getPrivateKey());

            deleteRSAKeys();

            // Re-encrypt with OAEP and store at new location
            byte[] encryptedAESWithOAEP = RSAEncrypt(decryptedAESKey);
            String newEncodedEncryptedAES = new String(Base64.encode(encryptedAESWithOAEP, Base64.DEFAULT), StandardCharsets.UTF_8);
            storage.store(KEY_ALIAS, newEncodedEncryptedAES);
            storage.remove(OLD_KEY_ALIAS);

            Log.d(TAG, "Legacy AES key migrated successfully");
            return decryptedAESKey;
        } catch (CryptoException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException | IllegalArgumentException e) {
            Log.e(TAG, "Could not migrate legacy AES key. Will generate new key.", e);
            deleteAESKeys();
            return null;
        }
    }

    /**
     * Generates a new AES-256 key, encrypts it with RSA-OAEP, and stores it.
     *
     * @return the newly generated AES key bytes
     * @throws IncompatibleDeviceException if the device doesn't support required algorithms
     * @throws CryptoException if key generation or encryption fails unexpectedly
     */
    private byte[] generateNewAESKey() throws IncompatibleDeviceException, CryptoException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGen.init(AES_KEY_SIZE);
            byte[] decryptedAESKey = keyGen.generateKey().getEncoded();

            byte[] encryptedNewAES = RSAEncrypt(decryptedAESKey);
            String encodedEncryptedNewAESText = new String(Base64.encode(encryptedNewAES, Base64.DEFAULT), StandardCharsets.UTF_8);
            storage.store(KEY_ALIAS, encodedEncryptedNewAESText);
            
            Log.d(TAG, "New AES key generated and stored");
            return decryptedAESKey;
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "AES algorithm not available.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IncompatibleDeviceException e) {
            deleteRSAKeys();
            deleteAESKeys();
            throw e;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "Unexpected error while creating new AES key.", e);
            throw new CryptoException("Unexpected error while creating new AES key.", e);
        }
    }


    /**
     * Decrypts the given input bytes using a symmetric key (AES).
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

            // Detect format and decrypt accordingly to maintain backward compatibility
            if (isNewFormat(encryptedInput)) {
                return decryptNewFormat(encryptedInput, cipher, key);
            } else {
                return decryptLegacyFormat(encryptedInput, cipher, key);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
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
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "Error while decrypting the input.", e);
            throw new IncompatibleDeviceException(e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            /*
             * Any of this exceptions mean the encrypted input is somehow corrupted and cannot be recovered.
             * - BadPaddingException:
             *      Thrown if the input doesn't contain the proper padding bytes. In this case, if the input contains padding.
             * - IllegalBlockSizeException:
             *      Thrown only on encrypt mode.
             */
            throw new CryptoException("The AES encrypted input is corrupted and cannot be recovered. Please discard it.", e);
        }
    }

    /**
     * Checks if the encrypted input uses the new format with bundled IV.
     * New format structure: [FORMAT_MARKER][IV_LENGTH][IV][ENCRYPTED_DATA]
     *
     * @param encryptedInput the encrypted data to check
     * @return true if new format, false if legacy format
     */
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    boolean isNewFormat(byte[] encryptedInput) {

        // Boundary check
        if (encryptedInput == null || encryptedInput.length < 2) {
            return false;
        }

        if (encryptedInput[0] != FORMAT_MARKER) {
            return false;
        }

        // Check IV length is valid for AES-GCM (12 or 16 bytes)
        // AES is a 128 block size cipher ,which is 16 bytes
        // AES in GCM mode the recommended IV length is 12 bytes.
        // This 12-byte IV is then combined with a 4-byte internal counter to form the full 16-byte
        // input block for the underlying AES block cipher in counter mode (CTR), which GCM utilizes.
        // Thus checking for a 12 or 16 byte length
        int ivLength = encryptedInput[1] & 0xFF;
        if (ivLength != 12 && ivLength != 16) {
            return false;
        }

        // Verify minimum total length
        // Need: marker(1) + length(1) + IV(12-16) + GCM tag(16) + data(1+)
        int minLength = FORMAT_HEADER_LENGTH + ivLength + GCM_TAG_LENGTH + MIN_DATA_LENGTH;
        return encryptedInput.length >= minLength;
    }

    /**
     * Decrypts data in the new format (IV bundled with encrypted data).
     *
     * @param encryptedInput the encrypted input in new format
     * @param cipher         the cipher instance
     * @param key            the secret key
     * @return the decrypted data
     * @throws InvalidKeyException                if the key is invalid
     * @throws InvalidAlgorithmParameterException if the IV is invalid
     * @throws IllegalBlockSizeException          if the block size is invalid
     * @throws BadPaddingException                if padding is incorrect
     */
    @VisibleForTesting
    private byte[] decryptNewFormat(byte[] encryptedInput, Cipher cipher, SecretKey key)
            throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {

        // Read IV length (byte 1)
        int ivLength = encryptedInput[1] & 0xFF;

        // Extract IV (bytes 2 to 2+ivLength)
        byte[] iv = new byte[ivLength];
        System.arraycopy(encryptedInput, 2, iv, 0, ivLength);

        int encryptedDataOffset = 2 + ivLength;
        int encryptedDataLength = encryptedInput.length - encryptedDataOffset;

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedInput, encryptedDataOffset, encryptedDataLength);
    }

    /**
     * Decrypts data in the legacy format (IV stored separately in storage).
     * This maintains backward compatibility with credentials encrypted before the fix.
     *
     * @param encryptedInput the encrypted input in legacy format
     * @param cipher         the cipher instance
     * @param key            the secret key
     * @return the decrypted data
     * @throws InvalidKeyException                if the key is invalid
     * @throws InvalidAlgorithmParameterException if the IV is invalid
     * @throws IllegalBlockSizeException          if the block size is invalid
     * @throws BadPaddingException                if padding is incorrect
     * @throws CryptoException                    if the IV cannot be found in storage
     */
    @VisibleForTesting
    private byte[] decryptLegacyFormat(byte[] encryptedInput, Cipher cipher, SecretKey key)
            throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, CryptoException {
        // Retrieve IV from storage (legacy behavior)
        String encodedIV = storage.retrieveString(KEY_IV_ALIAS);
        if (TextUtils.isEmpty(encodedIV)) {
            encodedIV = storage.retrieveString(OLD_KEY_IV_ALIAS);
            if (TextUtils.isEmpty(encodedIV)) {
                throw new CryptoException("The encryption keys changed recently. You need to re-encrypt something first.", null);
            }
        }

        byte[] iv = Base64.decode(encodedIV, Base64.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedInput);
    }

    /**
     * Encrypts the given input bytes using a symmetric key (AES).
     * The AES key is stored protected by an asymmetric key pair (RSA).
     * <p>
     * The encrypted output uses a new format that bundles the IV with the encrypted data
     * to prevent IV collision issues when multiple credentials are stored.
     * Format: [FORMAT_MARKER(1)][IV_LENGTH(1)][IV(12-16)][ENCRYPTED_DATA(variable)]
     *
     * @param decryptedInput the input bytes to encrypt. There's no limit in size.
     * @return the encrypted output bytes with bundled IV
     * @throws CryptoException             if the RSA Key pair was deemed invalid and got deleted. Operation can be retried.
     * @throws IncompatibleDeviceException in the event the device can't understand the cryptographic settings required
     */
    public byte[] encrypt(byte[] decryptedInput) throws CryptoException, IncompatibleDeviceException {
        try {
            SecretKey key = new SecretKeySpec(getAESKey(), ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(decryptedInput);
            byte[] iv = cipher.getIV();

            // NEW FORMAT: Bundle IV with encrypted data to prevent collision issues
            // Format: [FORMAT_MARKER][IV_LENGTH][IV][ENCRYPTED_DATA]
            byte[] output = new byte[1 + 1 + iv.length + encrypted.length];
            output[0] = FORMAT_MARKER;
            output[1] = (byte) iv.length;
            System.arraycopy(iv, 0, output, 2, iv.length);
            System.arraycopy(encrypted, 0, output, 2 + iv.length, encrypted.length);

            return output;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
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
             *
             * Read more in https://developer.android.com/reference/javax/crypto/Cipher
             */
            Log.e(TAG, "Error while encrypting the input.", e);
            throw new IncompatibleDeviceException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            /*
             * - IllegalBlockSizeException:
             *      Thrown if no padding has been requested and the length is not multiple of block size.
             * - BadPaddingException:
             *      Thrown only on decrypt mode.
             */
            throw new CryptoException("The AES decrypted input is invalid.", e);
        }
    }

}
