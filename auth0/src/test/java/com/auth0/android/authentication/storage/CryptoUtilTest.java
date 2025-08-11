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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.robolectric.annotation.Config;
import org.robolectric.util.ReflectionHelpers;

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
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.verifyPrivate;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@RunWith(PowerMockRunner.class)
@PrepareForTest({CryptoUtil.class, KeyGenerator.class, TextUtils.class, Build.VERSION.class, Base64.class, Cipher.class, Log.class, KeyStore.class, KeyPairGenerator.class})
public class CryptoUtilTest {

    private static final String NEW_RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String OLD_RSA_PKCS1_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";
    private static final String CERTIFICATE_PRINCIPAL = "CN=Auth0.Android,O=Auth0";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_RSA = "RSA";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;

    private static final String APP_PACKAGE_NAME = "com.mycompany.myapp";
    private static final String BASE_ALIAS = "keyName";
    private static final String KEY_ALIAS = APP_PACKAGE_NAME + "." + BASE_ALIAS;
    private static final String OLD_KEY_ALIAS = BASE_ALIAS;
    private static final String KEY_IV_ALIAS = KEY_ALIAS + "_iv";
    private static final String OLD_KEY_IV_ALIAS = OLD_KEY_ALIAS + "_iv";

    private Storage storage;
    private Cipher rsaOaepCipher;
    private Cipher rsaPkcs1Cipher;
    private Cipher aesCipher;
    private KeyStore keyStore;
    private KeyPairGenerator keyPairGenerator;
    private KeyGenerator keyGenerator;
    private CryptoUtil cryptoUtil;
    private Context context;
    private KeyStore.PrivateKeyEntry mockRsaPrivateKeyEntry;
    private PrivateKey mockRsaPrivateKey;
    private Certificate mockRsaCertificate;
    private SecretKey mockAesSecretKey;
    private byte[] testAesKeyBytes;
    private byte[] testPlaintextData;
    private byte[] testCiphertextData;
    private byte[] testIvBytes;
    private String testEncodedIv;

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Log.class);
        PowerMockito.mockStatic(TextUtils.class);
        when(TextUtils.isEmpty(anyString())).then((Answer<Boolean>) invocation -> {
            String input = invocation.getArgument(0, String.class);
            return input == null || input.isEmpty();
        });
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.mockStatic(KeyStore.class);
        PowerMockito.mockStatic(KeyPairGenerator.class);
        PowerMockito.mockStatic(KeyGenerator.class);
        PowerMockito.mockStatic(Cipher.class);

        storage = PowerMockito.mock(Storage.class);
        rsaOaepCipher = PowerMockito.mock(Cipher.class);
        rsaPkcs1Cipher = PowerMockito.mock(Cipher.class);
        aesCipher = PowerMockito.mock(Cipher.class);
        keyStore = PowerMockito.mock(KeyStore.class);
        keyPairGenerator = PowerMockito.mock(KeyPairGenerator.class);
        keyGenerator = PowerMockito.mock(KeyGenerator.class);

        context = mock(Context.class);
        when(context.getPackageName()).thenReturn(APP_PACKAGE_NAME);
        when(context.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(mock(KeyguardManager.class));
        when(context.getApplicationContext()).thenReturn(mock(Context.class));

        mockRsaPrivateKey = PowerMockito.mock(PrivateKey.class);
        mockRsaCertificate = PowerMockito.mock(Certificate.class);
        mockRsaPrivateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        when(mockRsaPrivateKeyEntry.getPrivateKey()).thenReturn(mockRsaPrivateKey);
        when(mockRsaPrivateKeyEntry.getCertificate()).thenReturn(mockRsaCertificate);

        testAesKeyBytes = new byte[AES_KEY_SIZE / 8];
        for (int i = 0; i < testAesKeyBytes.length; i++) testAesKeyBytes[i] = (byte) i;
        mockAesSecretKey = new SecretKeySpec(testAesKeyBytes, ALGORITHM_AES);

        testPlaintextData = "auth0-rocks".getBytes(StandardCharsets.UTF_8);
        testCiphertextData = "encrypted-auth0-rocks".getBytes(StandardCharsets.UTF_8);
        testIvBytes = new byte[12];
        for (int i = 0; i < testIvBytes.length; i++) testIvBytes[i] = (byte) (i + 10);
        testEncodedIv = "base64EncodedGCMIV==";
        PowerMockito.when(Base64.encode(any(byte[].class), anyInt())).thenAnswer((Answer<byte[]>) invocation -> {
            byte[] input = invocation.getArgument(0);
            if (Arrays.equals(input, testIvBytes)) {
                return testEncodedIv.getBytes(StandardCharsets.UTF_8);
            }
            return java.util.Base64.getEncoder().encode(input);
        });
        PowerMockito.when(Base64.decode(anyString(), anyInt())).thenAnswer((Answer<byte[]>) invocation -> {
            String input = invocation.getArgument(0);
            if (input == null) return new byte[0];
            if (testEncodedIv.equals(input)) return testIvBytes;
            try {
                return java.util.Base64.getDecoder().decode(input);
            } catch (Exception e) {
                return input.getBytes(StandardCharsets.UTF_8);
            }
        });

        when(KeyStore.getInstance(ANDROID_KEY_STORE)).thenReturn(keyStore);
        when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE)).thenReturn(keyPairGenerator);
        when(KeyGenerator.getInstance(ALGORITHM_AES)).thenReturn(keyGenerator);

        PowerMockito.when(Cipher.getInstance(anyString())).thenAnswer((Answer<Cipher>) invocation -> {
            String transformation = invocation.getArgument(0, String.class);
            if (NEW_RSA_OAEP_TRANSFORMATION.equals(transformation)) {
                return rsaOaepCipher;
            } else if (OLD_RSA_PKCS1_TRANSFORMATION.equals(transformation)) {
                return rsaPkcs1Cipher;
            } else if (AES_TRANSFORMATION.equals(transformation)) {
                return aesCipher;
            }
            Assert.fail("Cipher.getInstance called with unexpected transformation: " + transformation);
            return null;
        });

        cryptoUtil = PowerMockito.spy(new CryptoUtil(context, storage, BASE_ALIAS));
    }

    @Test
    public void shouldThrowWhenRSAKeyAliasIsInvalid() {
        Assert.assertThrows("RSA and AES Key alias must be valid.", IllegalArgumentException.class, () -> new CryptoUtil(context, storage, " "));
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingRSAKeyPairRebuildingTheEntryOnAPI28AndUp() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);
        when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        when(keyStore.getKey(KEY_ALIAS, null)).thenReturn(mockRsaPrivateKey);
        when(keyStore.getCertificate(KEY_ALIAS)).thenReturn(mockRsaCertificate);
        whenNew(KeyStore.PrivateKeyEntry.class).withAnyArguments().thenReturn(mockRsaPrivateKeyEntry);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(mockRsaPrivateKeyEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingPrivateKeyForOldKeyAlias() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);
        when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        when(keyStore.containsAlias(OLD_KEY_ALIAS)).thenReturn(true);
        when(keyStore.getKey(OLD_KEY_ALIAS, null)).thenReturn(mockRsaPrivateKey);
        when(keyStore.getCertificate(OLD_KEY_ALIAS)).thenReturn(mockRsaCertificate);
        whenNew(KeyStore.PrivateKeyEntry.class).withAnyArguments().thenReturn(mockRsaPrivateKeyEntry);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(mockRsaPrivateKeyEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingRSAKeyPairOnAPI28AndUp() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);
        KeyStore.PrivateKeyEntry entry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(entry);
        PrivateKey privateKey = null;
        when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        when(keyStore.getKey(KEY_ALIAS, null)).thenReturn(privateKey);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(entry));
    }

    @Test
    @Config(sdk = 27)
    public void shouldUseExistingRSAKeyPairOnAPI27AndDown() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 27);
        when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(mockRsaPrivateKeyEntry);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(mockRsaPrivateKeyEntry));
    }

    @Test
    public void shouldDeleteRSAAndAESKeysAndThrowOnUnrecoverableEntryExceptionWhenTryingToObtainRSAKeys() throws Exception {
        Assert.assertThrows("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", CryptoException.class, () -> {
            when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
            when(keyStore.getEntry(KEY_ALIAS, null)).thenThrow(new UnrecoverableEntryException());
            cryptoUtil.getRSAKeyEntry();
        });
        verify(keyStore).deleteEntry(KEY_ALIAS);
        verify(keyStore).deleteEntry(OLD_KEY_ALIAS);
        verifyCleanupAESKeys();
    }

    @Test
    public void shouldDeleteRSAAndAESKeysAndThrowOnSingleIOExceptionWhenTryingToObtainRSAKeys() throws Exception {
        Assert.assertThrows("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", CryptoException.class, () -> {
            doThrow(new IOException()).doNothing().when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));
            cryptoUtil.getRSAKeyEntry();
        });
        verify(keyStore).deleteEntry(KEY_ALIAS);
        verify(keyStore).deleteEntry(OLD_KEY_ALIAS);
        verifyCleanupAESKeys();
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnDoubleIOExceptionWhenTryingToObtainRSAKeys() throws Exception {
        Assert.assertThrows("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", CryptoException.class, () -> {
            doThrow(new IOException()).when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));
            cryptoUtil.getRSAKeyEntry();
        });
        verifyCleanupAESKeys();
    }

    @Test
    public void shouldThrowOnKeyStoreExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            PowerMockito.when(KeyStore.getInstance(ANDROID_KEY_STORE)).thenThrow(new KeyStoreException());
            new CryptoUtil(context, storage, BASE_ALIAS).getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnCertificateExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            doThrow(new CertificateException()).when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));
            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnProviderExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            doThrow(new ProviderException()).when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));
            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnNoSuchProviderExceptionWhenTryingToObtainRSAKeys() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 19);
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
            when(keyStore.containsAlias(OLD_KEY_ALIAS)).thenReturn(false);
            KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(mock(KeyPairGeneratorSpec.class));
            PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);
            PowerMockito.when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE)).thenThrow(new NoSuchProviderException());
            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToObtainRSAKeys() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 19);
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
            when(keyStore.containsAlias(OLD_KEY_ALIAS)).thenReturn(false);
            KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(mock(KeyPairGeneratorSpec.class));
            PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);
            PowerMockito.when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE)).thenThrow(new NoSuchAlgorithmException());
            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnInvalidAlgorithmParameterExceptionWhenTryingToObtainRSAKeys() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 19);
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
            when(keyStore.containsAlias(OLD_KEY_ALIAS)).thenReturn(false);
            KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(mock(KeyPairGeneratorSpec.class));
            PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);
            doThrow(new InvalidAlgorithmParameterException()).when(keyPairGenerator).initialize(any(AlgorithmParameterSpec.class));
            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldCreateAESKeyIfStoredOneIsEmpty() throws Exception {
        String emptyString = "";
        byte[] emptyEncryptedKey = new byte[0];
        when(storage.retrieveString(KEY_ALIAS)).thenReturn(emptyString);
        PowerMockito.when(Base64.decode(emptyString, Base64.DEFAULT)).thenReturn(emptyEncryptedKey);
        doThrow(new CryptoException("failed", new BadPaddingException())).when(cryptoUtil).RSADecrypt(emptyEncryptedKey);
        when(rsaPkcs1Cipher.doFinal(emptyEncryptedKey)).thenThrow(new BadPaddingException());
        doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();

        byte[] newlyEncryptedKey = "new-encrypted-key".getBytes(StandardCharsets.UTF_8);
        String newlyEncodedKey = "newBase64Key";
        when(keyGenerator.generateKey()).thenReturn(mockAesSecretKey);
        doReturn(newlyEncryptedKey).when(cryptoUtil).RSAEncrypt(testAesKeyBytes);
        PowerMockito.when(Base64.encode(newlyEncryptedKey, Base64.DEFAULT)).thenReturn(newlyEncodedKey.getBytes(StandardCharsets.UTF_8));

        final byte[] aesKey = cryptoUtil.getAESKey();
        assertThat(aesKey, is(testAesKeyBytes));
    }

    @Test
    public void shouldUseExistingAESKey() throws Exception {
        String aesString = "non null string";
        byte[] encryptedAesKey = aesString.getBytes(StandardCharsets.UTF_8);

        PowerMockito.when(Base64.decode(aesString, Base64.DEFAULT)).thenReturn(encryptedAesKey);
        when(storage.retrieveString(KEY_ALIAS)).thenReturn(aesString);
        doReturn(testAesKeyBytes).when(cryptoUtil).RSADecrypt(encryptedAesKey);

        final byte[] aesKey = cryptoUtil.getAESKey();
        assertThat(aesKey, is(notNullValue()));
        assertThat(aesKey, is(testAesKeyBytes));
    }

    @Test
    public void shouldRSAEncryptData() throws Exception {
        byte[] sampleInput = new byte[]{0, 1, 2, 3, 4, 5};
        byte[] sampleOutput = new byte[]{99, 33, 11};

        doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        when(rsaOaepCipher.doFinal(sampleInput)).thenReturn(sampleOutput);

        final byte[] output = cryptoUtil.RSAEncrypt(sampleInput);

        Mockito.verify(rsaOaepCipher).init(Cipher.ENCRYPT_MODE, mockRsaCertificate);
        assertThat(output, is(sampleOutput));
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnBadPaddingExceptionWhenTryingToRSAEncrypt() throws Exception {
        Assert.assertThrows("The RSA decrypted input is invalid.", CryptoException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            when(rsaOaepCipher.doFinal(any(byte[].class))).thenThrow(new BadPaddingException());
            cryptoUtil.RSAEncrypt(new byte[0]);
        });
        verifyCleanupAESKeys();
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnIllegalBlockSizeExceptionWhenTryingToRSAEncrypt() throws Exception {
        Assert.assertThrows("The RSA decrypted input is invalid.", CryptoException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            when(rsaOaepCipher.doFinal(any(byte[].class))).thenThrow(new IllegalBlockSizeException());
            cryptoUtil.RSAEncrypt(new byte[0]);
        });
        verifyCleanupAESKeys();
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToRSAEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.when(Cipher.getInstance(NEW_RSA_OAEP_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());
            cryptoUtil.RSAEncrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToRSAEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.when(Cipher.getInstance(NEW_RSA_OAEP_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());
            cryptoUtil.RSAEncrypt(new byte[0]);
        });
    }

    @Test
    public void shouldRSADecryptData() throws Exception {
        byte[] sampleInput = "RSA-OAEP-encrypted-input".getBytes(StandardCharsets.UTF_8);
        byte[] sampleOutput = new byte[]{99, 33, 11};
        doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        when(rsaOaepCipher.doFinal(sampleInput)).thenReturn(sampleOutput);

        final byte[] output = cryptoUtil.RSADecrypt(sampleInput);

        Mockito.verify(rsaOaepCipher).init(Cipher.DECRYPT_MODE, mockRsaPrivateKey);
        assertThat(output, is(sampleOutput));
    }

    @Test
    public void shouldThrowOnInvalidKeyExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            doThrow(new InvalidKeyException()).when(rsaOaepCipher).init(Cipher.DECRYPT_MODE, mockRsaPrivateKey);
            cryptoUtil.RSADecrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.when(Cipher.getInstance(NEW_RSA_OAEP_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());
            cryptoUtil.RSADecrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class.", IncompatibleDeviceException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.when(Cipher.getInstance(NEW_RSA_OAEP_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());
            cryptoUtil.RSADecrypt(new byte[0]);
        });
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnBadPaddingExceptionWhenTryingToRSADecrypt() throws Exception {
        Assert.assertThrows("The RSA encrypted input is corrupted and cannot be recovered. Please discard it.", CryptoException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            when(rsaOaepCipher.doFinal(any(byte[].class))).thenThrow(new BadPaddingException());
            cryptoUtil.RSADecrypt(new byte[0]);
        });
        verifyCleanupAESKeys();
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnIllegalBlockSizeExceptionWhenTryingToRSADecrypt() throws Exception {
        Assert.assertThrows("The RSA encrypted input is corrupted and cannot be recovered. Please discard it.", CryptoException.class, () -> {
            doReturn(mockRsaPrivateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            when(rsaOaepCipher.doFinal(any(byte[].class))).thenThrow(new IllegalBlockSizeException());
            cryptoUtil.RSADecrypt(new byte[0]);
        });
        verifyCleanupAESKeys();
    }

    @Test
    public void shouldAESEncryptData() throws Exception {
        ArgumentCaptor<SecretKey> secretKeyCaptor = ArgumentCaptor.forClass(SecretKey.class);
        doReturn(testAesKeyBytes).when(cryptoUtil).getAESKey();
        when(aesCipher.doFinal(testPlaintextData)).thenReturn(testCiphertextData);
        when(aesCipher.getIV()).thenReturn(testIvBytes);

        final byte[] encrypted = cryptoUtil.encrypt(testPlaintextData);

        Mockito.verify(aesCipher).init(eq(Cipher.ENCRYPT_MODE), secretKeyCaptor.capture());
        assertThat(secretKeyCaptor.getValue().getEncoded(), is(testAesKeyBytes));
        Mockito.verify(storage).store(KEY_IV_ALIAS, testEncodedIv);
        assertThat(encrypted, is(testCiphertextData));
    }

    @Test
    public void shouldAESDecryptData() throws Exception {
        ArgumentCaptor<SecretKey> secretKeyCaptor = ArgumentCaptor.forClass(SecretKey.class);
        ArgumentCaptor<IvParameterSpec> ivParameterSpecArgumentCaptor = ArgumentCaptor.forClass(IvParameterSpec.class);
        doReturn(testAesKeyBytes).when(cryptoUtil).getAESKey();
        when(storage.retrieveString(KEY_IV_ALIAS)).thenReturn(testEncodedIv);
        when(aesCipher.doFinal(testCiphertextData)).thenReturn(testPlaintextData);

        final byte[] decrypted = cryptoUtil.decrypt(testCiphertextData);

        Mockito.verify(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyCaptor.capture(), ivParameterSpecArgumentCaptor.capture());
        assertThat(secretKeyCaptor.getValue().getEncoded(), is(testAesKeyBytes));
        assertThat(ivParameterSpecArgumentCaptor.getValue().getIV(), is(testIvBytes));
        assertThat(decrypted, is(testPlaintextData));
    }

    private KeyPairGeneratorSpec.Builder newKeyPairGeneratorSpecBuilder(KeyPairGeneratorSpec expectedBuilderOutput) {
        KeyPairGeneratorSpec.Builder builder = PowerMockito.mock(KeyPairGeneratorSpec.Builder.class);
        when(builder.setAlias(anyString())).thenReturn(builder);
        when(builder.setSubject(any(X500Principal.class))).thenReturn(builder);
        when(builder.setKeySize(anyInt())).thenReturn(builder);
        when(builder.setSerialNumber(any(BigInteger.class))).thenReturn(builder);
        when(builder.setStartDate(any(Date.class))).thenReturn(builder);
        when(builder.setEndDate(any(Date.class))).thenReturn(builder);
        when(builder.setEncryptionRequired()).thenReturn(builder);
        when(builder.build()).thenReturn(expectedBuilderOutput);
        return builder;
    }

    private KeyGenParameterSpec.Builder newKeyGenParameterSpecBuilder(KeyGenParameterSpec expectedBuilderOutput) {
        KeyGenParameterSpec.Builder builder = PowerMockito.mock(KeyGenParameterSpec.Builder.class);
        when(builder.setKeySize(anyInt())).thenReturn(builder);
        when(builder.setCertificateSubject(any(X500Principal.class))).thenReturn(builder);
        when(builder.setCertificateSerialNumber(any(BigInteger.class))).thenReturn(builder);
        when(builder.setCertificateNotBefore(any(Date.class))).thenReturn(builder);
        when(builder.setCertificateNotAfter(any(Date.class))).thenReturn(builder);
        when(builder.setEncryptionPaddings(any(String[].class))).thenReturn(builder);
        when(builder.setDigests(any(String[].class))).thenReturn(builder);
        when(builder.setBlockModes(anyString())).thenReturn(builder);
        when(builder.build()).thenReturn(expectedBuilderOutput);
        return builder;
    }

    private CryptoUtil newCryptoUtilSpy() throws Exception {
        CryptoUtil cryptoUtil = PowerMockito.spy(new CryptoUtil(context, storage, BASE_ALIAS));
        PowerMockito.mockStatic(KeyStore.class);
        when(KeyStore.getInstance(ANDROID_KEY_STORE)).thenReturn(keyStore);
        PowerMockito.mockStatic(KeyPairGenerator.class);
        when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE)).thenReturn(keyPairGenerator);
        PowerMockito.mockStatic(KeyGenerator.class);
        when(KeyGenerator.getInstance(ALGORITHM_AES)).thenReturn(keyGenerator);
        PowerMockito.mockStatic(Cipher.class);

        when(Cipher.getInstance(anyString())).then((Answer<Cipher>) invocation -> {
            String transformation = invocation.getArgument(0, String.class);
            if (NEW_RSA_OAEP_TRANSFORMATION.equals(transformation)) {
                return rsaOaepCipher;
            } else if (OLD_RSA_PKCS1_TRANSFORMATION.equals(transformation)) {
                return rsaPkcs1Cipher;
            } else if (AES_TRANSFORMATION.equals(transformation)) {
                return aesCipher;
            }
            return null;
        });
        return cryptoUtil;
    }

    private void verifyCleanupAESKeys() throws Exception {
        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_IV_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_IV_ALIAS);
    }

    private void verifyNoCleanupAESKeys() throws Exception {
        Mockito.verify(storage, never()).remove(KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_IV_ALIAS);
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(OLD_KEY_IV_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
    }
}
