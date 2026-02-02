package com.auth0.android.authentication.storage;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

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
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * This test class uses MockedStatic for static method mocking (KeyStore, Cipher, KeyGenerator,
 * KeyPairGenerator, Base64, TextUtils) and relies on Robolectric shadows for Android SDK
 * builder classes like KeyGenParameterSpec.Builder and KeyPairGeneratorSpec.Builder.
 * Note: Robolectric 4.x requires SDK 21+ (Android 5.0+).
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class CryptoUtilTest {

    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String OLD_RSA_PKCS1_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";
    private static final String CERTIFICATE_PRINCIPAL = "CN=Auth0.Android,O=Auth0";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_RSA = "RSA";
    private static final int RSA_KEY_SIZE = 2048;

    private final Storage storage = Mockito.mock(Storage.class);
    private final Cipher rsaOaepCipher = Mockito.mock(Cipher.class);
    private final Cipher rsaPkcs1Cipher = Mockito.mock(Cipher.class);
    private final Cipher aesCipher = Mockito.mock(Cipher.class);
    private final KeyStore keyStore = Mockito.mock(KeyStore.class);
    private final KeyPairGenerator keyPairGenerator = Mockito.mock(KeyPairGenerator.class);
    private final KeyGenerator keyGenerator = Mockito.mock(KeyGenerator.class);

    private MockedStatic<KeyStore> keyStoreMock;
    private MockedStatic<Cipher> cipherMock;
    private MockedStatic<KeyGenerator> keyGeneratorMock;
    private MockedStatic<KeyPairGenerator> keyPairGeneratorMock;
    private MockedStatic<Base64> base64Mock;
    private MockedStatic<TextUtils> textUtilsMock;

    private CryptoUtil cryptoUtil;

    private static final String APP_PACKAGE_NAME = "com.mycompany.myapp";
    private static final String BASE_ALIAS = "keyName";
    private static final String KEY_ALIAS = APP_PACKAGE_NAME + "." + BASE_ALIAS;
    private static final String OLD_KEY_ALIAS = BASE_ALIAS;
    private Context context;

    //Android KeyStore not accessible using Robolectric
    //Must test using white-box approach
    //Ref: https://github.com/robolectric/robolectric/issues/1518

    @Before
    public void setUp() throws Exception {
        // Initialize MockedStatic instances for static method mocking
        keyStoreMock = Mockito.mockStatic(KeyStore.class);
        keyStoreMock.when(() -> KeyStore.getInstance(ANDROID_KEY_STORE)).thenReturn(keyStore);

        cipherMock = Mockito.mockStatic(Cipher.class);
        cipherMock.when(() -> Cipher.getInstance(anyString())).thenAnswer((Answer<Cipher>) invocation -> {
            String transformation = invocation.getArgument(0, String.class);
            if (RSA_TRANSFORMATION.equals(transformation)) {
                return rsaOaepCipher;
            } else if (OLD_RSA_PKCS1_TRANSFORMATION.equals(transformation)) {
                return rsaPkcs1Cipher;
            } else if (AES_TRANSFORMATION.equals(transformation)) {
                return aesCipher;
            }
            return null;
        });

        keyGeneratorMock = Mockito.mockStatic(KeyGenerator.class);
        keyGeneratorMock.when(() -> KeyGenerator.getInstance(ALGORITHM_AES)).thenReturn(keyGenerator);

        keyPairGeneratorMock = Mockito.mockStatic(KeyPairGenerator.class);
        keyPairGeneratorMock.when(() -> KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE))
                .thenReturn(keyPairGenerator);

        base64Mock = Mockito.mockStatic(Base64.class, Mockito.CALLS_REAL_METHODS);
        textUtilsMock = Mockito.mockStatic(TextUtils.class, Mockito.CALLS_REAL_METHODS);

        context = mock(Context.class);
        when(context.getPackageName()).thenReturn(APP_PACKAGE_NAME);
        cryptoUtil = newCryptoUtilSpy();
    }

    @After
    public void tearDown() {
        // Close all MockedStatic instances to prevent memory leaks
        if (keyStoreMock != null) keyStoreMock.close();
        if (cipherMock != null) cipherMock.close();
        if (keyGeneratorMock != null) keyGeneratorMock.close();
        if (keyPairGeneratorMock != null) keyPairGeneratorMock.close();
        if (base64Mock != null) base64Mock.close();
        if (textUtilsMock != null) textUtilsMock.close();
    }

    /*
     * GET RSA KEY tests
     */

    @Test
    public void shouldThrowWhenRSAKeyAliasIsInvalid() {
        Assert.assertThrows("RSA and AES Key alias must be valid.", IllegalArgumentException.class, () -> {
            //noinspection deprecation
            new CryptoUtil(RuntimeEnvironment.application, storage, " ");
        });
    }

    @Test
    @Config(sdk = 21)
    public void shouldNotCreateProtectedRSAKeyPairIfMissingAndLockScreenEnabled() throws Exception {
        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        ArgumentCaptor<AlgorithmParameterSpec> specCaptor = ArgumentCaptor.forClass(AlgorithmParameterSpec.class);

        //Set LockScreen as Enabled but with null device credential intent
        KeyguardManager kService = Mockito.mock(KeyguardManager.class);
        Mockito.when(context.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        Mockito.when(kService.isKeyguardSecure()).thenReturn(true);
        Mockito.when(kService.createConfirmDeviceCredentialIntent(nullable(CharSequence.class), nullable(CharSequence.class))).thenReturn(null);

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(keyPairGenerator).initialize(specCaptor.capture());
        Mockito.verify(keyPairGenerator).generateKeyPair();

        // Verify the spec properties directly (Robolectric shadows the real builder)
        KeyPairGeneratorSpec spec = (KeyPairGeneratorSpec) specCaptor.getValue();
        assertThat(spec.getKeySize(), is(2048));
        assertThat(spec.getKeystoreAlias(), is(KEY_ALIAS));
        assertThat(spec.getSerialNumber(), is(BigInteger.ONE));
        // Note: setEncryptionRequired was NOT called since authIntent is null

        assertThat(spec.getSubjectDN(), is(notNullValue()));
        assertThat(spec.getSubjectDN().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(spec.getStartDate(), is(notNullValue()));
        long diffMillis = spec.getStartDate().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(spec.getEndDate(), is(notNullValue()));
        diffMillis = spec.getEndDate().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 21)
    public void shouldCreateUnprotectedRSAKeyPairIfMissingAndLockScreenDisabledOnAPI21() throws Exception {

        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        ArgumentCaptor<AlgorithmParameterSpec> specCaptor = ArgumentCaptor.forClass(AlgorithmParameterSpec.class);

        //Set LockScreen as Disabled
        KeyguardManager kService = Mockito.mock(KeyguardManager.class);
        Mockito.when(context.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        Mockito.when(kService.isKeyguardSecure()).thenReturn(false);
        Mockito.when(kService.createConfirmDeviceCredentialIntent(any(CharSequence.class), any(CharSequence.class))).thenReturn(null);

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(keyPairGenerator).initialize(specCaptor.capture());
        Mockito.verify(keyPairGenerator).generateKeyPair();

        // Verify the spec properties directly
        KeyPairGeneratorSpec spec = (KeyPairGeneratorSpec) specCaptor.getValue();
        assertThat(spec.getKeySize(), is(2048));
        assertThat(spec.getKeystoreAlias(), is(KEY_ALIAS));
        assertThat(spec.getSerialNumber(), is(BigInteger.ONE));

        assertThat(spec.getSubjectDN(), is(notNullValue()));
        assertThat(spec.getSubjectDN().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(spec.getStartDate(), is(notNullValue()));
        long diffMillis = spec.getStartDate().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(spec.getEndDate(), is(notNullValue()));
        diffMillis = spec.getEndDate().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 21)
    public void shouldCreateProtectedRSAKeyPairIfMissingAndLockScreenEnabledOnAPI21() throws Exception {

        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        ArgumentCaptor<AlgorithmParameterSpec> specCaptor = ArgumentCaptor.forClass(AlgorithmParameterSpec.class);

        //Set LockScreen as Enabled
        KeyguardManager kService = Mockito.mock(KeyguardManager.class);
        Mockito.when(context.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        Mockito.when(kService.isKeyguardSecure()).thenReturn(true);
        Mockito.when(kService.createConfirmDeviceCredentialIntent(any(), any())).thenReturn(new Intent());

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(keyPairGenerator).initialize(specCaptor.capture());
        Mockito.verify(keyPairGenerator).generateKeyPair();

        // Verify the spec properties directly
        KeyPairGeneratorSpec spec = (KeyPairGeneratorSpec) specCaptor.getValue();
        assertThat(spec.getKeySize(), is(2048));
        assertThat(spec.getKeystoreAlias(), is(KEY_ALIAS));
        assertThat(spec.getSerialNumber(), is(BigInteger.ONE));
        // Note: setEncryptionRequired WAS called since lock screen is enabled with valid authIntent
        assertThat(spec.isEncryptionRequired(), is(true));

        assertThat(spec.getSubjectDN(), is(notNullValue()));
        assertThat(spec.getSubjectDN().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(spec.getStartDate(), is(notNullValue()));
        long diffMillis = spec.getStartDate().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(spec.getEndDate(), is(notNullValue()));
        diffMillis = spec.getEndDate().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 23)
    public void shouldCreateRSAKeyPairIfMissingOnAPI23AndUp() throws Exception {

        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        ArgumentCaptor<AlgorithmParameterSpec> specCaptor = ArgumentCaptor.forClass(AlgorithmParameterSpec.class);

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(keyPairGenerator).initialize(specCaptor.capture());
        Mockito.verify(keyPairGenerator).generateKeyPair();

        // Verify the spec properties directly
        KeyGenParameterSpec spec = (KeyGenParameterSpec) specCaptor.getValue();
        assertThat(spec.getKeySize(), is(2048));
        assertThat(spec.getKeystoreAlias(), is(KEY_ALIAS));
        assertThat(spec.getCertificateSerialNumber(), is(BigInteger.ONE));
        assertThat(spec.getEncryptionPaddings(), is(new String[]{KeyProperties.ENCRYPTION_PADDING_RSA_OAEP}));
        assertThat(spec.getDigests(), is(new String[]{KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256}));
        assertThat(spec.getBlockModes(), is(new String[]{KeyProperties.BLOCK_MODE_ECB}));

        assertThat(spec.getCertificateSubject(), is(notNullValue()));
        assertThat(spec.getCertificateSubject().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(spec.getCertificateNotBefore(), is(notNullValue()));
        long diffMillis = spec.getCertificateNotBefore().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(spec.getCertificateNotAfter(), is(notNullValue()));
        diffMillis = spec.getCertificateNotAfter().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldCreateRSAKeyPairIfMissingOnAPI28AndUp() throws Exception {

        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        ArgumentCaptor<AlgorithmParameterSpec> specCaptor = ArgumentCaptor.forClass(AlgorithmParameterSpec.class);

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(keyPairGenerator).initialize(specCaptor.capture());
        Mockito.verify(keyPairGenerator).generateKeyPair();

        // Verify the spec properties directly
        KeyGenParameterSpec spec = (KeyGenParameterSpec) specCaptor.getValue();
        assertThat(spec.getKeySize(), is(2048));
        assertThat(spec.getKeystoreAlias(), is(KEY_ALIAS));
        assertThat(spec.getCertificateSerialNumber(), is(BigInteger.ONE));
        assertThat(spec.getEncryptionPaddings(), is(new String[]{KeyProperties.ENCRYPTION_PADDING_RSA_OAEP}));
        assertThat(spec.getDigests(), is(new String[]{KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256}));
        assertThat(spec.getBlockModes(), is(new String[]{KeyProperties.BLOCK_MODE_ECB}));

        assertThat(spec.getCertificateSubject(), is(notNullValue()));
        assertThat(spec.getCertificateSubject().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(spec.getCertificateNotBefore(), is(notNullValue()));
        long diffMillis = spec.getCertificateNotBefore().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(spec.getCertificateNotAfter(), is(notNullValue()));
        diffMillis = spec.getCertificateNotAfter().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldCreateNewRSAKeyPairWhenExistingRSAKeyPairCannotBeRebuiltOnAPI28AndUp() throws Exception {
        PrivateKey privateKey = Mockito.mock(PrivateKey.class);

        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        Mockito.when(keyStore.getKey(KEY_ALIAS, null)).thenReturn(privateKey).thenReturn(null);
        Mockito.when(keyStore.getCertificate(KEY_ALIAS)).thenReturn(null);
        KeyStore.PrivateKeyEntry expectedEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        ArgumentCaptor<AlgorithmParameterSpec> specCaptor = ArgumentCaptor.forClass(AlgorithmParameterSpec.class);

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(keyPairGenerator).initialize(specCaptor.capture());
        Mockito.verify(keyPairGenerator).generateKeyPair();

        // Verify the spec properties directly
        KeyGenParameterSpec spec = (KeyGenParameterSpec) specCaptor.getValue();
        assertThat(spec.getKeySize(), is(2048));
        assertThat(spec.getKeystoreAlias(), is(KEY_ALIAS));
        assertThat(spec.getCertificateSerialNumber(), is(BigInteger.ONE));
        assertThat(spec.getEncryptionPaddings(), is(new String[]{KeyProperties.ENCRYPTION_PADDING_RSA_OAEP}));
        assertThat(spec.getDigests(), is(new String[]{KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256}));
        assertThat(spec.getBlockModes(), is(new String[]{KeyProperties.BLOCK_MODE_ECB}));

        assertThat(spec.getCertificateSubject(), is(notNullValue()));
        assertThat(spec.getCertificateSubject().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(spec.getCertificateNotBefore(), is(notNullValue()));
        long diffMillis = spec.getCertificateNotBefore().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(spec.getCertificateNotAfter(), is(notNullValue()));
        diffMillis = spec.getCertificateNotAfter().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L)));

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingRSAKeyPairRebuildingTheEntryOnAPI28AndUp() throws Exception {
        PrivateKey privateKey = Mockito.mock(PrivateKey.class);
        Certificate certificate = Mockito.mock(Certificate.class);

        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        Mockito.when(keyStore.getKey(KEY_ALIAS, null)).thenReturn(privateKey);
        Mockito.when(keyStore.getCertificate(KEY_ALIAS)).thenReturn(certificate);

        // Use mockConstruction to intercept PrivateKeyEntry constructor
        try (MockedConstruction<KeyStore.PrivateKeyEntry> mockedConstruction = Mockito.mockConstruction(
                KeyStore.PrivateKeyEntry.class,
                (mock, context) -> {
                    // Capture constructor arguments
                })) {

            KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();

            assertThat(rsaEntry, is(notNullValue()));
            assertThat(mockedConstruction.constructed().size(), is(1));
            assertThat(rsaEntry, is(mockedConstruction.constructed().get(0)));
        }
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingPrivateKeyForOldKeyAlias() throws Exception {
        PrivateKey privateKey = Mockito.mock(PrivateKey.class);
        Certificate certificate = Mockito.mock(Certificate.class);

        Mockito.when(keyStore.containsAlias(OLD_KEY_ALIAS)).thenReturn(true);
        Mockito.when(keyStore.getKey(OLD_KEY_ALIAS, null)).thenReturn(privateKey);
        Mockito.when(keyStore.getCertificate(OLD_KEY_ALIAS)).thenReturn(certificate);

        try (MockedConstruction<KeyStore.PrivateKeyEntry> mockedConstruction = Mockito.mockConstruction(
                KeyStore.PrivateKeyEntry.class,
                (mock, context) -> {
                })) {

            KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();

            assertThat(rsaEntry, is(notNullValue()));
            assertThat(mockedConstruction.constructed().size(), is(1));
            assertThat(rsaEntry, is(mockedConstruction.constructed().get(0)));
        }
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingRSAKeyPairOnAPI28AndUp() throws Exception {
        KeyStore.PrivateKeyEntry entry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(entry);
        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(entry));
    }

    @Test
    @Config(sdk = 27)
    public void shouldUseExistingRSAKeyPairOnAPI27AndDown() throws Exception {
        KeyStore.PrivateKeyEntry entry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        Mockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(entry);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(entry));
    }

    @Test
    public void shouldDeleteRSAAndAESKeysAndThrowOnUnrecoverableEntryExceptionWhenTryingToObtainRSAKeys() throws Exception {
        Assert.assertThrows("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", CryptoException.class, () -> {
            KeyStore.PrivateKeyEntry entry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
            Mockito.when(keyStore.getEntry(KEY_ALIAS, null))
                    .thenThrow(new UnrecoverableEntryException())
                    .thenReturn(entry);

            cryptoUtil.getRSAKeyEntry();
        });

        Mockito.verify(keyStore).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldDeleteRSAAndAESKeysAndThrowOnSingleIOExceptionWhenTryingToObtainRSAKeys() throws Exception {
        Assert.assertThrows("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", CryptoException.class, () -> {
            //In this variant, the first call to keyStore.load() - when we're reading the key - throws an
            //exception, but the second one - when we delete the entry on cleanup - does not. Though
            //unlikely, this test provides coverage of that scenario.
            doThrow(new IOException()).doNothing().when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));

            cryptoUtil.getRSAKeyEntry();
        });

        Mockito.verify(keyStore).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnDoubleIOExceptionWhenTryingToObtainRSAKeys() throws Exception {
        Assert.assertThrows("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", CryptoException.class, () -> {
            //In this variant, the first call to keyStore.load() - when we're reading the key - throws an
            //exception, and the second one - when we delete the entry on cleanup - does as well.
            //This would seem to be the more likely scenario. In this case we don't have any way
            //to clean up the RSA key.
            doThrow(new IOException()).when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));

            cryptoUtil.getRSAKeyEntry();
        });

        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldThrowOnKeyStoreExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Mockito.when(KeyStore.getInstance(anyString()))
                    .thenThrow(new KeyStoreException());

            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnCertificateExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            doThrow(new CertificateException()).when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));

            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnProviderExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            doThrow(new ProviderException()).when(keyStore).load(nullable(KeyStore.LoadStoreParameter.class));

            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnNoSuchProviderExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);

            keyPairGeneratorMock.when(() -> KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE))
                    .thenThrow(new NoSuchProviderException());

            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);

            keyPairGeneratorMock.when(() -> KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE))
                    .thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnInvalidAlgorithmParameterExceptionWhenTryingToObtainRSAKeys() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Mockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);

            doThrow(new InvalidAlgorithmParameterException()).when(keyPairGenerator).initialize(any(AlgorithmParameterSpec.class));

            cryptoUtil.getRSAKeyEntry();
        });
    }

    /*
     * GET AES KEY tests
     */

    @Test
    public void shouldCreateAESKeyIfMissing() throws Exception {
        byte[] sampleBytes = new byte[]{0, 1, 2, 3, 4, 5};
        base64Mock.when(() -> Base64.encode(sampleBytes, Base64.DEFAULT)).thenReturn("data".getBytes());
        Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(null);
        Mockito.when(storage.retrieveString(OLD_KEY_ALIAS)).thenReturn(null);
        textUtilsMock.when(() -> TextUtils.isEmpty(null)).thenReturn(true);

        SecretKey secretKey = Mockito.mock(SecretKey.class);
        Mockito.when(keyGenerator.generateKey()).thenReturn(secretKey);
        Mockito.when(secretKey.getEncoded()).thenReturn(sampleBytes);
        Mockito.doReturn(sampleBytes).when(cryptoUtil).RSAEncrypt(sampleBytes);

        final byte[] aesKey = cryptoUtil.getAESKey();

        Mockito.verify(keyGenerator).init(256);
        Mockito.verify(keyGenerator).generateKey();
        Mockito.verify(storage).store(KEY_ALIAS, "data");

        assertThat(aesKey, is(notNullValue()));
        assertThat(aesKey, is(sampleBytes));
    }

    @Test
    public void shouldCreateAESKeyIfStoredOneIsEmpty() throws BadPaddingException, IllegalBlockSizeException {
        String emptyString = "";
        byte[] sampleBytes = emptyString.getBytes();
        byte[] sampleOutput = new byte[]{99, 33, 11};
        base64Mock.when(() -> Base64.decode(emptyString, Base64.DEFAULT)).thenReturn(sampleBytes);
        base64Mock.when(() -> Base64.encode(sampleBytes, Base64.DEFAULT)).thenReturn("data".getBytes());
        Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(emptyString);
        doReturn(sampleBytes).when(cryptoUtil).RSAEncrypt(sampleBytes);

        //Assume RSAKeyEntry exists
        PrivateKey privateKey = Mockito.mock(PrivateKey.class);
        KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
        doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        doReturn(sampleOutput).when(rsaOaepCipher).doFinal(sampleBytes);

        SecretKey secretKey = Mockito.mock(SecretKey.class);
        Mockito.when(secretKey.getEncoded()).thenReturn(sampleBytes);
        Mockito.when(keyGenerator.generateKey()).thenReturn(secretKey);


        final byte[] aesKey = cryptoUtil.getAESKey();

        Mockito.verify(keyGenerator).init(256);
        Mockito.verify(keyGenerator).generateKey();
        Mockito.verify(storage).store(KEY_ALIAS, "data");

        assertThat(aesKey, is(notNullValue()));
        assertThat(aesKey, is(sampleBytes));
    }

    @Test
    public void shouldUseExistingAESKey() {
        final int AES_KEY_SIZE = 256;
        byte[] sampleBytes = new byte[AES_KEY_SIZE / 8];
        Arrays.fill(sampleBytes, (byte) 1);
        String aesString = "non null string";

        base64Mock.when(() -> Base64.decode(aesString, Base64.DEFAULT)).thenReturn(sampleBytes);
        Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(aesString);
        doReturn(sampleBytes).when(cryptoUtil).RSADecrypt(sampleBytes);

        final byte[] aesKey = cryptoUtil.getAESKey();
        assertThat(aesKey, is(notNullValue()));
        assertThat(aesKey, is(sampleBytes));
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenCreatingAESKey() throws Exception {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(null);
            Mockito.when(storage.retrieveString(OLD_KEY_ALIAS)).thenReturn(null);
            textUtilsMock.when(() -> TextUtils.isEmpty(null)).thenReturn(true);
            Mockito.when(KeyGenerator.getInstance(ALGORITHM_AES))
                    .thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.getAESKey();
        });
    }

    /*
     * RSA ENCRYPT tests
     */

    @Test
    public void shouldRSAEncryptData() throws Exception {
        byte[] sampleInput = new byte[]{0, 1, 2, 3, 4, 5};
        byte[] sampleOutput = new byte[]{99, 33, 11};

        PublicKey publicKey = Mockito.mock(PublicKey.class);
        Certificate certificate = Mockito.mock(Certificate.class);
        doReturn(publicKey).when(certificate).getPublicKey();
        KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        doReturn(certificate).when(privateKeyEntry).getCertificate();
        doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        doReturn(sampleOutput).when(rsaOaepCipher).doFinal(sampleInput);

        final byte[] output = cryptoUtil.RSAEncrypt(sampleInput);

        Mockito.verify(rsaOaepCipher).init(eq(Cipher.ENCRYPT_MODE), eq(publicKey), any(AlgorithmParameterSpec.class));
        assertThat(output, is(sampleOutput));
    }

    @Test
    public void shouldThrowOnInvalidKeyExceptionWhenTryingToRSAEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            byte[] sampleBytes = new byte[0];
            PublicKey publicKey = Mockito.mock(PublicKey.class);
            Certificate certificate = Mockito.mock(Certificate.class);
            doReturn(publicKey).when(certificate).getPublicKey();
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaOaepCipher);
            doThrow(new InvalidKeyException()).when(rsaOaepCipher).init(eq(Cipher.ENCRYPT_MODE), eq(publicKey), any(AlgorithmParameterSpec.class));

            cryptoUtil.RSAEncrypt(sampleBytes);
        });
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnBadPaddingExceptionWhenTryingToRSAEncrypt() throws Exception {
        Assert.assertThrows("The RSA decrypted input is invalid.", CryptoException.class, () -> {

            byte[] sampleBytes = new byte[0];
            Certificate certificate = Mockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaOaepCipher);
            Mockito.when(rsaOaepCipher.doFinal(sampleBytes)).thenThrow(new BadPaddingException());

            cryptoUtil.RSAEncrypt(sampleBytes);
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnIllegalBlockSizeExceptionWhenTryingToRSAEncrypt() throws Exception {
        Assert.assertThrows("The RSA decrypted input is invalid.", CryptoException.class, () -> {
            Certificate certificate = Mockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaOaepCipher);
            Mockito.when(rsaOaepCipher.doFinal(any(byte[].class))).thenThrow(new IllegalBlockSizeException());

            cryptoUtil.RSAEncrypt(new byte[0]);
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToRSAEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Certificate certificate = Mockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.RSAEncrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToRSAEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Certificate certificate = Mockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

            cryptoUtil.RSAEncrypt(new byte[0]);
        });
    }

    /*
     * RSA DECRYPT tests
     */

    @Test
    public void shouldRSADecryptData() throws Exception {
        byte[] sampleInput = new byte[]{0, 1, 2, 3, 4, 5};
        byte[] sampleOutput = new byte[]{99, 33, 11};

        PrivateKey privateKey = Mockito.mock(PrivateKey.class);
        KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
        doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
        doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        doReturn(sampleOutput).when(rsaOaepCipher).doFinal(sampleInput);

        final byte[] output = cryptoUtil.RSADecrypt(sampleInput);

        Mockito.verify(rsaOaepCipher).init(eq(Cipher.DECRYPT_MODE), eq(privateKey), any(AlgorithmParameterSpec.class));
        assertThat(output, is(sampleOutput));
    }

    @Test
    public void shouldThrowOnInvalidKeyExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            byte[] sampleBytes = new byte[0];
            PrivateKey privateKey = Mockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaOaepCipher);
            doThrow(new InvalidKeyException()).when(rsaOaepCipher).init(eq(Cipher.DECRYPT_MODE), eq(privateKey), any(AlgorithmParameterSpec.class));

            cryptoUtil.RSADecrypt(sampleBytes);
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PrivateKey privateKey = Mockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.RSADecrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PrivateKey privateKey = Mockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            Mockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

            cryptoUtil.RSADecrypt(new byte[0]);
        });
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnBadPaddingExceptionWhenTryingToRSADecrypt() throws Exception {
        Assert.assertThrows("The RSA encrypted input is corrupted and cannot be recovered. Please discard it.", CryptoException.class, () -> {
            PrivateKey privateKey = Mockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();

            doThrow(new BadPaddingException()).when(rsaOaepCipher).doFinal(any(byte[].class));
            cryptoUtil.RSADecrypt(new byte[0]);
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnIllegalBlockSizeExceptionWhenTryingToRSADecrypt() throws Exception {
        Assert.assertThrows("The RSA encrypted input is corrupted and cannot be recovered. Please discard it.", CryptoException.class, () -> {
            PrivateKey privateKey = Mockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = Mockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();

            doThrow(new IllegalBlockSizeException()).when(rsaOaepCipher).doFinal(any(byte[].class));
            cryptoUtil.RSADecrypt(new byte[0]);
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS);
        Mockito.verify(storage).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage).remove(OLD_KEY_ALIAS + "_iv");
    }

    /*
     * MAIN ENCRYPT (AES) tests
     */

    @Test
    public void shouldAESEncryptData() throws Exception {
        ArgumentCaptor<SecretKey> secretKeyCaptor = ArgumentCaptor.forClass(SecretKey.class);
        byte[] aesKey = "aes-decrypted-key".getBytes();
        byte[] data = "data".getBytes();
        byte[] encryptedData = new byte[]{0, 1, 2, 3, 4, 5};
        byte[] iv = new byte[]{99, 99, 11, 11, 22, 22, 33, 33, 44, 44, 55, 55}; // 12-byte IV for AES-GCM

        doReturn(aesKey).when(cryptoUtil).getAESKey();
        doReturn(encryptedData).when(aesCipher).doFinal(data);
        Mockito.when(aesCipher.doFinal(data)).thenReturn(encryptedData);
        Mockito.when(aesCipher.getIV()).thenReturn(iv);

        final byte[] encrypted = cryptoUtil.encrypt(data);

        Mockito.verify(aesCipher).init(eq(Cipher.ENCRYPT_MODE), secretKeyCaptor.capture());
        assertThat(secretKeyCaptor.getValue(), is(notNullValue()));
        assertThat(secretKeyCaptor.getValue().getAlgorithm(), is(ALGORITHM_AES));
        assertThat(secretKeyCaptor.getValue().getEncoded(), is(aesKey));

        // IV is NO LONGER stored in storage - it's bundled with the encrypted data
        Mockito.verify(storage, never()).store(eq(KEY_ALIAS + "_iv"), anyString());

        assertThat(encrypted, is(notNullValue()));
        assertThat(encrypted.length, is(1 + 1 + iv.length + encryptedData.length));
        assertThat(encrypted[0], is((byte) 0x01));
        assertThat(encrypted[1], is((byte) iv.length));

        // Verify IV is correctly embedded
        byte[] extractedIV = new byte[iv.length];
        System.arraycopy(encrypted, 2, extractedIV, 0, iv.length);
        assertThat(extractedIV, is(iv));

        // Verify encrypted data is correctly embedded
        byte[] extractedEncrypted = new byte[encryptedData.length];
        System.arraycopy(encrypted, 2 + iv.length, extractedEncrypted, 0, encryptedData.length);
        assertThat(extractedEncrypted, is(encryptedData));
    }

    @Test
    public void shouldThrowOnCryptoExceptionOnRSAKeyReadingWhenTryingToAESEncrypt() {
        Assert.assertThrows(CryptoException.class, () -> {
            base64Mock.when(() -> Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

            doThrow(new CryptoException("err", null)).when(cryptoUtil).getRSAKeyEntry();
            cryptoUtil.encrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnCryptoExceptionOnAESKeyReadingWhenTryingToAESEncrypt() {
        Assert.assertThrows(CryptoException.class, () -> {
            doThrow(new CryptoException("err", null)).when(cryptoUtil).getAESKey();
            cryptoUtil.encrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnIncompatibleDeviceExceptionOnRSAKeyReadingWhenTryingToAESEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            base64Mock.when(() -> Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

            doThrow(new IncompatibleDeviceException(null)).when(cryptoUtil).getRSAKeyEntry();
            cryptoUtil.encrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnIncompatibleDeviceExceptionOnAESKeyReadingWhenTryingToAESEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            doThrow(new IncompatibleDeviceException(null)).when(cryptoUtil).getAESKey();
            cryptoUtil.encrypt(new byte[0]);
        });
    }


    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToAESEncrypt() {
        Assert.assertThrows(IncompatibleDeviceException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();

            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

            cryptoUtil.encrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToAESEncrypt() throws Exception {
        Assert.assertThrows(IncompatibleDeviceException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();

            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.encrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnInvalidKeyExceptionWhenTryingToAESEncrypt() throws Exception {
        Exception exception = null;
        ArgumentCaptor<SecretKey> secretKeyArgumentCaptor = ArgumentCaptor.forClass(SecretKey.class);
        byte[] aesKeyBytes = new byte[]{11, 22, 33};
        try {
            doReturn(aesKeyBytes).when(cryptoUtil).getAESKey();

            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            doThrow(new InvalidKeyException()).when(aesCipher).init(eq(Cipher.ENCRYPT_MODE), secretKeyArgumentCaptor.capture());

            cryptoUtil.encrypt(new byte[0]);
        } catch (IncompatibleDeviceException e) {
            exception = e;
        }
        assertThat(exception, is(notNullValue()));
        assertThat(secretKeyArgumentCaptor.getValue().getAlgorithm(), is("AES"));
        assertThat(secretKeyArgumentCaptor.getValue().getEncoded(), is(aesKeyBytes));
    }


    @Test
    public void shouldThrowButNotDeleteAESKeysOnBadPaddingExceptionWhenTryingToAESEncrypt() throws Exception {
        Assert.assertThrows("The AES decrypted input is invalid.", CryptoException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();
            doThrow(new BadPaddingException()).when(aesCipher)
                    .doFinal(any(byte[].class));

            cryptoUtil.encrypt(new byte[0]);
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldThrowButNotDeleteAESKeysOnIllegalBlockSizeExceptionWhenTryingToAESEncrypt() throws Exception {
        Assert.assertThrows("The AES decrypted input is invalid.", CryptoException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();
            doThrow(new IllegalBlockSizeException()).when(aesCipher)
                    .doFinal(any(byte[].class));

            cryptoUtil.encrypt(new byte[0]);
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS + "_iv");
    }


    /*
     * NEW FORMAT tests
     */
    @Test
    public void shouldDetectNewFormatWithValidMarkerAndIVLength12() {
        // Create new format data: [0x01][12][IV(12 bytes)][encrypted+tag(17 bytes minimum)]
        // Min length: 1 + 1 + 12 + 16 (tag) + 1 (data) = 31 bytes
        byte[] newFormatData = new byte[31];
        newFormatData[0] = 0x01; // FORMAT_MARKER
        newFormatData[1] = 12;   // IV length
        for (int i = 2; i < newFormatData.length; i++) {
            newFormatData[i] = (byte) i;
        }

        boolean result = cryptoUtil.isNewFormat(newFormatData);

        assertThat(result, is(true));
    }

    @Test
    public void shouldDetectNewFormatWithValidMarkerAndIVLength16() {
        // Create new format data: [0x01][16][IV(16 bytes)][encrypted+tag(17 bytes minimum)]
        // Min length: 1 + 1 + 16 + 16 (tag) + 1 (data) = 35 bytes
        byte[] newFormatData = new byte[35];
        newFormatData[0] = 0x01; // FORMAT_MARKER
        newFormatData[1] = 16;   // IV length
        // Fill with dummy data
        for (int i = 2; i < newFormatData.length; i++) {
            newFormatData[i] = (byte) i;
        }

        boolean result = cryptoUtil.isNewFormat(newFormatData);

        assertThat(result, is(true));
    }

    @Test
    public void shouldNotDetectNewFormatWithInvalidMarker() {
        // Create data with wrong marker
        byte[] invalidData = new byte[30];
        invalidData[0] = 0x02; // Wrong marker
        invalidData[1] = 12;   // Valid IV length

        boolean result = cryptoUtil.isNewFormat(invalidData);

        assertThat(result, is(false));
    }

    @Test
    public void shouldNotDetectNewFormatWithInvalidIVLength() {
        // Create data with invalid IV length
        byte[] invalidData = new byte[30];
        invalidData[0] = 0x01; // Valid marker
        invalidData[1] = 10;   // Invalid IV length (not 12 or 16)

        boolean result = cryptoUtil.isNewFormat(invalidData);

        assertThat(result, is(false));
    }

    @Test
    public void shouldExtractIVFromNewFormatCorrectly() {
        byte[] iv = new byte[]{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120};
        byte[] encryptedPayload = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}; // At least 17 bytes (16 tag + 1 data)

        byte[] newFormatData = new byte[1 + 1 + iv.length + encryptedPayload.length];
        newFormatData[0] = 0x01;
        newFormatData[1] = (byte) iv.length;
        System.arraycopy(iv, 0, newFormatData, 2, iv.length);
        System.arraycopy(encryptedPayload, 0, newFormatData, 2 + iv.length, encryptedPayload.length);

        // Verify format detection
        assertThat(cryptoUtil.isNewFormat(newFormatData), is(true));

        // Manually extract and verify IV
        int ivLength = newFormatData[1] & 0xFF;
        assertThat(ivLength, is(12));

        byte[] extractedIV = new byte[ivLength];
        System.arraycopy(newFormatData, 2, extractedIV, 0, ivLength);
        assertThat(extractedIV, is(iv));

        // Verify encrypted payload position
        int dataOffset = 2 + ivLength;
        int dataLength = newFormatData.length - dataOffset;
        assertThat(dataLength, is(encryptedPayload.length));
    }

    @Test
    public void shouldVerifyMinimumLengthRequirements() {
        // Minimum valid new format with 12-byte IV:
        // 1 (marker) + 1 (length) + 12 (IV) + 16 (GCM tag) + 1 (data) = 31 bytes
        byte[] minValid12 = new byte[31];
        minValid12[0] = 0x01;
        minValid12[1] = 12;
        assertThat(cryptoUtil.isNewFormat(minValid12), is(true));

        // One byte less should fail
        byte[] tooShort12 = new byte[30];
        tooShort12[0] = 0x01;
        tooShort12[1] = 12;
        assertThat(cryptoUtil.isNewFormat(tooShort12), is(false));

        // Minimum valid new format with 16-byte IV:
        // 1 (marker) + 1 (length) + 16 (IV) + 16 (GCM tag) + 1 (data) = 35 bytes
        byte[] minValid16 = new byte[35];
        minValid16[0] = 0x01;
        minValid16[1] = 16;
        assertThat(cryptoUtil.isNewFormat(minValid16), is(true));

        // One byte less should fail
        byte[] tooShort16 = new byte[34];
        tooShort16[0] = 0x01;
        tooShort16[1] = 16;
        assertThat(cryptoUtil.isNewFormat(tooShort16), is(false));
    }

    @Test
    public void shouldRejectInvalidIVLengthsInNewFormat() {
        byte[] ivLength0 = new byte[19];
        ivLength0[0] = 0x01;
        ivLength0[1] = 0;
        assertThat(cryptoUtil.isNewFormat(ivLength0), is(false));

        byte[] ivLength13 = new byte[32];
        ivLength13[0] = 0x01;
        ivLength13[1] = 13;
        assertThat(cryptoUtil.isNewFormat(ivLength13), is(false));

        byte[] ivLength14 = new byte[33];
        ivLength14[0] = 0x01;
        ivLength14[1] = 14;
        assertThat(cryptoUtil.isNewFormat(ivLength14), is(false));

        byte[] ivLength15 = new byte[34];
        ivLength15[0] = 0x01;
        ivLength15[1] = 15;
        assertThat(cryptoUtil.isNewFormat(ivLength15), is(false));

        byte[] ivLength255 = new byte[274];
        ivLength255[0] = 0x01;
        ivLength255[1] = (byte) 255;
        assertThat(cryptoUtil.isNewFormat(ivLength255), is(false));
    }

    /*
     * MIGRATION SCENARIO tests - Testing backward compatibility and format coexistence
     */
    @Test
    public void shouldDecryptLegacyFormatDataWithIVInStorage() throws Exception {
        ArgumentCaptor<IvParameterSpec> ivCaptor = ArgumentCaptor.forClass(IvParameterSpec.class);
        byte[] aesKey = "aes-decrypted-key".getBytes();
        byte[] originalData = "sensitive-data".getBytes();
        byte[] encryptedData = new byte[]{10, 20, 30, 40, 50, 60}; // Old format
        byte[] iv = new byte[]{99, 99, 11, 11, 22, 22, 33, 33, 44, 44, 55, 55}; // 12-byte IV

        // Setup: Old format has IV stored separately in storage
        doReturn(aesKey).when(cryptoUtil).getAESKey();
        Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("encoded-iv-data");
        base64Mock.when(() -> Base64.decode("encoded-iv-data", Base64.DEFAULT)).thenReturn(iv);
        Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
        Mockito.when(aesCipher.doFinal(encryptedData)).thenReturn(originalData);

        // Execute: Decrypt old format data (should be detected as legacy format)
        final byte[] decrypted = cryptoUtil.decrypt(encryptedData);

        // Verify: Should detect as legacy format and use IV from storage
        assertThat(cryptoUtil.isNewFormat(encryptedData), is(false));
        Mockito.verify(storage).retrieveString(KEY_ALIAS + "_iv");
        Mockito.verify(aesCipher).init(eq(Cipher.DECRYPT_MODE), any(SecretKey.class), ivCaptor.capture());
        assertThat(ivCaptor.getValue().getIV(), is(iv));
        assertThat(decrypted, is(originalData));
    }

    @Test
    public void shouldMigrateFromLegacyFormatToNewFormat() throws Exception {
        byte[] aesKey = "aes-decrypted-key".getBytes();
        byte[] originalData = "sensitive-data".getBytes();
        byte[] oldEncryptedData = new byte[]{10, 20, 30, 40, 50, 60};
        byte[] oldIv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        // New encrypted data must be at least 17 bytes (16-byte GCM tag + 1+ bytes data)
        byte[] newEncryptedData = new byte[20]; // 20 bytes to be safe
        for (int i = 0; i < newEncryptedData.length; i++) {
            newEncryptedData[i] = (byte) (50 + i);
        }
        byte[] newIv = new byte[]{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22};

        doReturn(aesKey).when(cryptoUtil).getAESKey();
        Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);

        // Step 1: Decrypt old format (IV from storage)
        Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("old-encoded-iv");
        base64Mock.when(() -> Base64.decode("old-encoded-iv", Base64.DEFAULT)).thenReturn(oldIv);
        Mockito.when(aesCipher.doFinal(oldEncryptedData)).thenReturn(originalData);

        byte[] decryptedOld = cryptoUtil.decrypt(oldEncryptedData);
        assertThat(decryptedOld, is(originalData));
        assertThat(cryptoUtil.isNewFormat(oldEncryptedData), is(false));

        // Step 2: Re-encrypt in new format (IV bundled)
        Mockito.when(aesCipher.doFinal(originalData)).thenReturn(newEncryptedData);
        Mockito.when(aesCipher.getIV()).thenReturn(newIv);

        byte[] reEncrypted = cryptoUtil.encrypt(originalData);

        // Verify new format structure
        assertThat(reEncrypted[0], is((byte) 0x01)); // FORMAT_MARKER
        assertThat(reEncrypted[1], is((byte) newIv.length));
        assertThat(cryptoUtil.isNewFormat(reEncrypted), is(true));

        // Extract and verify IV is bundled
        byte[] extractedIV = new byte[newIv.length];
        System.arraycopy(reEncrypted, 2, extractedIV, 0, newIv.length);
        assertThat(extractedIV, is(newIv));

        // Step 3: Decrypt new format (IV bundled in data)
        Mockito.when(aesCipher.doFinal(any(byte[].class), anyInt(), anyInt())).thenReturn(originalData);

        byte[] decryptedNew = cryptoUtil.decrypt(reEncrypted);
        assertThat(decryptedNew, is(originalData));

        // Verify IV not stored in storage for new format
        Mockito.verify(storage, never()).store(eq(KEY_ALIAS + "_iv"), anyString());
    }

    @Test
    public void shouldDecryptBothLegacyAndNewFormatInSameSession() throws Exception {
        byte[] aesKey = "aes-decrypted-key".getBytes();
        byte[] dataA = "credential-A".getBytes();
        byte[] dataB = "credential-B".getBytes();

        // Old format encrypted data (no format marker, starts with random byte)
        byte[] oldEncrypted = new byte[]{10, 20, 30, 40, 50, 60};
        byte[] oldIv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

        // New format encrypted data (with format marker and bundled IV)
        byte[] newIv = new byte[]{99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88};
        byte[] newEncryptedPayload = new byte[17]; // 17 bytes (16 tag + 1 data min)
        for (int i = 0; i < newEncryptedPayload.length; i++) {
            newEncryptedPayload[i] = (byte) (70 + i * 10);
        }
        byte[] newEncrypted = new byte[1 + 1 + newIv.length + newEncryptedPayload.length];
        newEncrypted[0] = 0x01; // FORMAT_MARKER
        newEncrypted[1] = (byte) newIv.length;
        System.arraycopy(newIv, 0, newEncrypted, 2, newIv.length);
        System.arraycopy(newEncryptedPayload, 0, newEncrypted, 2 + newIv.length, newEncryptedPayload.length);

        doReturn(aesKey).when(cryptoUtil).getAESKey();
        Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);

        // Decrypt old format first
        Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("old-iv-encoded");
        base64Mock.when(() -> Base64.decode("old-iv-encoded", Base64.DEFAULT)).thenReturn(oldIv);
        Mockito.when(aesCipher.doFinal(oldEncrypted)).thenReturn(dataA);

        byte[] decryptedOld = cryptoUtil.decrypt(oldEncrypted);
        assertThat(decryptedOld, is(dataA));

        // Decrypt new format next
        Mockito.when(aesCipher.doFinal(any(byte[].class), anyInt(), anyInt())).thenReturn(dataB);

        byte[] decryptedNew = cryptoUtil.decrypt(newEncrypted);
        assertThat(decryptedNew, is(dataB));

        // Verify format detection worked correctly for both
        assertThat(cryptoUtil.isNewFormat(oldEncrypted), is(false));
        assertThat(cryptoUtil.isNewFormat(newEncrypted), is(true));

        // Verify storage was only accessed for old format
        Mockito.verify(storage, Mockito.atLeastOnce()).retrieveString(KEY_ALIAS + "_iv");
    }

    /*
     * MAIN DECRYPT (AES) tests
     */

    @Test
    public void shouldAESDecryptData() throws Exception {
        ArgumentCaptor<SecretKey> secretKeyCaptor = ArgumentCaptor.forClass(SecretKey.class);
        ArgumentCaptor<IvParameterSpec> ivParameterSpecCaptor = ArgumentCaptor.forClass(IvParameterSpec.class);
        byte[] aesKey = "aes-decrypted-key".getBytes();
        byte[] originalData = "data".getBytes();
        byte[] encryptedPayload = new byte[]{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 13, 14, 15, 16, 17}; // 17 bytes (16 tag + 1 data)
        byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}; // 12-byte IV

        // Build new format data: [0x01][IV_LENGTH][IV][ENCRYPTED_DATA]
        byte[] newFormatData = new byte[1 + 1 + iv.length + encryptedPayload.length];
        newFormatData[0] = 0x01; // FORMAT_MARKER
        newFormatData[1] = (byte) iv.length; // IV length
        System.arraycopy(iv, 0, newFormatData, 2, iv.length);
        System.arraycopy(encryptedPayload, 0, newFormatData, 2 + iv.length, encryptedPayload.length);

        doReturn(aesKey).when(cryptoUtil).getAESKey();
        Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
        Mockito.when(aesCipher.doFinal(any(byte[].class), anyInt(), anyInt())).thenReturn(originalData);

        final byte[] decrypted = cryptoUtil.decrypt(newFormatData);

        assertThat(cryptoUtil.isNewFormat(newFormatData), is(true));

        Mockito.verify(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyCaptor.capture(), ivParameterSpecCaptor.capture());
        assertThat(secretKeyCaptor.getValue(), is(notNullValue()));
        assertThat(secretKeyCaptor.getValue().getAlgorithm(), is(ALGORITHM_AES));
        assertThat(secretKeyCaptor.getValue().getEncoded(), is(aesKey));
        assertThat(ivParameterSpecCaptor.getValue(), is(notNullValue()));
        assertThat(ivParameterSpecCaptor.getValue().getIV(), is(iv));
        assertThat(decrypted, is(originalData));
    }

    @Test
    public void shouldThrowOnCryptoExceptionOnRSAKeyReadingWhenTryingToAESDecrypt() {
        Assert.assertThrows(CryptoException.class, () -> {
            base64Mock.when(() -> Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

            doThrow(new CryptoException("err", null)).when(cryptoUtil).getRSAKeyEntry();
            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnCryptoExceptionOnAESKeyReadingWhenTryingToAESDecrypt() {
        Assert.assertThrows(CryptoException.class, () -> {
            doThrow(new CryptoException("err", null)).when(cryptoUtil).getAESKey();
            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnIncompatibleDeviceExceptionOnRSAKeyReadingWhenTryingToAESDecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            base64Mock.when(() -> Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            Mockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

            doThrow(new IncompatibleDeviceException(null)).when(cryptoUtil).getRSAKeyEntry();
            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnIncompatibleDeviceExceptionOnAESKeyReadingWhenTryingToAESDecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            doThrow(new IncompatibleDeviceException(null)).when(cryptoUtil).getAESKey();
            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToAESDecrypt() {
        Assert.assertThrows(IncompatibleDeviceException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();

            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToAESDecrypt() {
        Assert.assertThrows(IncompatibleDeviceException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();

            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnEmptyInitializationVectorWhenTryingToAESDecryptWithOldFormat() {
        Assert.assertThrows("The encryption keys changed recently. You need to re-encrypt something first.", CryptoException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();
            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("");
            Mockito.when(storage.retrieveString(BASE_ALIAS + "_iv")).thenReturn("");

            cryptoUtil.decrypt(new byte[]{12, 1, 3, 14, 15, 16, 17});
        });
    }

    @Test
    public void shouldThrowOnInvalidKeyExceptionWhenTryingToAESDecrypt() throws Exception {
        Exception exception = null;
        byte[] aesKeyBytes = new byte[]{11, 22, 33};
        byte[] ivBytes = new byte[]{99, 22};
        ArgumentCaptor<SecretKey> secretKeyArgumentCaptor = ArgumentCaptor.forClass(SecretKey.class);
        ArgumentCaptor<IvParameterSpec> ivParameterSpecArgumentCaptor = ArgumentCaptor.forClass(IvParameterSpec.class);

        try {
            doReturn(aesKeyBytes).when(cryptoUtil).getAESKey();
            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            base64Mock.when(() -> Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new InvalidKeyException()).when(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyArgumentCaptor.capture(), ivParameterSpecArgumentCaptor.capture());

            cryptoUtil.decrypt(new byte[]{12, 13, 14, 15, 16});
        } catch (IncompatibleDeviceException e) {
            exception = e;
        }

        assertThat(exception, is(notNullValue()));
        assertThat(secretKeyArgumentCaptor.getValue().getAlgorithm(), is("AES"));
        assertThat(secretKeyArgumentCaptor.getValue().getEncoded(), is(aesKeyBytes));
        assertThat(ivParameterSpecArgumentCaptor.getValue().getIV(), is(ivBytes));
    }

    @Test
    public void shouldThrowOnInvalidAlgorithmParameterExceptionWhenTryingToAESDecrypt() throws Exception {
        Exception exception = null;
        byte[] aesKeyBytes = new byte[]{11, 22, 33};
        byte[] ivBytes = new byte[]{99, 22};
        ArgumentCaptor<SecretKey> secretKeyArgumentCaptor = ArgumentCaptor.forClass(SecretKey.class);
        ArgumentCaptor<IvParameterSpec> ivParameterSpecArgumentCaptor = ArgumentCaptor.forClass(IvParameterSpec.class);

        try {
            doReturn(aesKeyBytes).when(cryptoUtil).getAESKey();
            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            base64Mock.when(() -> Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new InvalidAlgorithmParameterException()).when(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyArgumentCaptor.capture(), ivParameterSpecArgumentCaptor.capture());
            cryptoUtil.decrypt(new byte[]{12, 13, 14, 15, 16, 17});
        } catch (IncompatibleDeviceException e) {
            exception = e;
        }

        assertThat(exception, is(notNullValue()));
        assertThat(secretKeyArgumentCaptor.getValue().getAlgorithm(), is("AES"));
        assertThat(secretKeyArgumentCaptor.getValue().getEncoded(), is(aesKeyBytes));
        assertThat(ivParameterSpecArgumentCaptor.getValue().getIV(), is(ivBytes));
    }

    @Test
    public void shouldThrowButNotDeleteAESKeysOnBadPaddingExceptionWhenTryingToAESDecrypt() throws Exception {
        Assert.assertThrows("The AES encrypted input is corrupted and cannot be recovered. Please discard it.", CryptoException.class, () -> {
            byte[] aesKeyBytes = new byte[]{11, 22, 33};
            byte[] ivBytes = new byte[]{99, 22};

            doReturn(aesKeyBytes).when(cryptoUtil).getAESKey();
            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            base64Mock.when(() -> Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new BadPaddingException()).when(aesCipher).doFinal(any(byte[].class));

            cryptoUtil.decrypt(new byte[]{12, 13, 14, 15, 16, 17});
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS + "_iv");
    }

    @Test
    public void shouldThrowButNotDeleteAESKeysOnIllegalBlockSizeExceptionWhenTryingToAESDecrypt() throws Exception {
        Assert.assertThrows("The AES encrypted input is corrupted and cannot be recovered. Please discard it.", CryptoException.class, () -> {
            byte[] aesKeyBytes = new byte[]{11, 22, 33};
            doReturn(aesKeyBytes).when(cryptoUtil).getAESKey();
            Mockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            Mockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            byte[] ivBytes = new byte[]{99, 22};
            base64Mock.when(() -> Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new IllegalBlockSizeException()).when(aesCipher).doFinal(any(byte[].class));

            cryptoUtil.decrypt(new byte[]{12, 13, 14, 15, 16, 17});
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS + "_iv");
    }


    @Test
    public void shouldDetectAndMigratePKCS1KeyToOAEP() throws Exception {
        CryptoUtil cryptoUtil = newCryptoUtilSpy();

        byte[] aesKeyBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        byte[] encryptedAESKeyPKCS1 = new byte[]{20, 21, 22, 23, 24};
        byte[] encryptedAESKeyOAEP = new byte[]{30, 31, 32, 33, 34};
        String encodedEncryptedAESPKCS1 = "pkcs1_encrypted_key";
        String encodedEncryptedAESOAEP = "oaep_encrypted_key";

        when(storage.retrieveString(eq(KEY_ALIAS))).thenReturn(encodedEncryptedAESPKCS1);
        when(storage.retrieveString(eq(OLD_KEY_ALIAS))).thenReturn(null);
        base64Mock.when(() -> Base64.decode(encodedEncryptedAESPKCS1, Base64.DEFAULT)).thenReturn(encryptedAESKeyPKCS1);
        base64Mock.when(() -> Base64.encode(encryptedAESKeyOAEP, Base64.DEFAULT))
                .thenReturn(encodedEncryptedAESOAEP.getBytes(StandardCharsets.UTF_8));

        IncompatibleDeviceException incompatibleException = new IncompatibleDeviceException(
                new KeyStoreException("Incompatible padding mode")
        );
        doThrow(incompatibleException).when(cryptoUtil).RSADecrypt(encryptedAESKeyPKCS1);

        when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        KeyStore.PrivateKeyEntry mockKeyEntry = mock(KeyStore.PrivateKeyEntry.class);
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        Certificate mockCertificate = mock(Certificate.class);
        PublicKey mockPublicKey = mock(PublicKey.class);
        when(mockKeyEntry.getPrivateKey()).thenReturn(mockPrivateKey);
        when(mockKeyEntry.getCertificate()).thenReturn(mockCertificate);
        when(mockCertificate.getPublicKey()).thenReturn(mockPublicKey);
        when(keyStore.getEntry(eq(KEY_ALIAS), nullable(KeyStore.ProtectionParameter.class)))
                .thenReturn(mockKeyEntry);

        when(rsaPkcs1Cipher.doFinal(encryptedAESKeyPKCS1)).thenReturn(aesKeyBytes);

        doReturn(encryptedAESKeyOAEP).when(cryptoUtil).RSAEncrypt(aesKeyBytes);

        byte[] result = cryptoUtil.getAESKey();

        assertThat(result, is(aesKeyBytes));

        Mockito.verify(rsaPkcs1Cipher).init(Cipher.DECRYPT_MODE, mockPrivateKey);
        Mockito.verify(rsaPkcs1Cipher).doFinal(encryptedAESKeyPKCS1);

        Mockito.verify(keyStore).deleteEntry(KEY_ALIAS);
        Mockito.verify(storage).store(KEY_ALIAS, encodedEncryptedAESOAEP);
    }

    @Test
    public void shouldHandleKeyStoreErrorDuringMigration() throws Exception {
        CryptoUtil cryptoUtil = newCryptoUtilSpy();

        String encodedEncryptedAES = "encrypted_key";
        byte[] encryptedAESBytes = new byte[]{5, 6, 7, 8, 9};

        when(storage.retrieveString(eq(KEY_ALIAS))).thenReturn(encodedEncryptedAES);
        when(storage.retrieveString(eq(OLD_KEY_ALIAS))).thenReturn(null);
        base64Mock.when(() -> Base64.decode(encodedEncryptedAES, Base64.DEFAULT)).thenReturn(encryptedAESBytes);

        CryptoException cryptoException = new CryptoException(
                "Decryption failed",
                new ProviderException("KeyStore error code -1000")
        );
        doThrow(cryptoException).when(cryptoUtil).RSADecrypt(encryptedAESBytes);

        byte[] newAESKey = new byte[]{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26};
        SecretKey mockSecretKey = mock(SecretKey.class);
        when(mockSecretKey.getEncoded()).thenReturn(newAESKey);
        when(keyGenerator.generateKey()).thenReturn(mockSecretKey);

        byte[] encryptedNewKey = new byte[]{30, 31, 32, 33};
        doReturn(encryptedNewKey).when(cryptoUtil).RSAEncrypt(any(byte[].class));
        String encodedNewKey = "new_generated_key";
        base64Mock.when(() -> Base64.encode(encryptedNewKey, Base64.DEFAULT))
                .thenReturn(encodedNewKey.getBytes(StandardCharsets.UTF_8));

        byte[] result = cryptoUtil.getAESKey();

        Mockito.verify(storage, times(1)).remove(KEY_ALIAS);

        assertThat(result, is(newAESKey));
        Mockito.verify(storage).store(KEY_ALIAS, encodedNewKey);
    }

    @Test
    public void shouldUseOAEPDirectlyForNewUsers() throws Exception {
        CryptoUtil cryptoUtil = newCryptoUtilSpy();

        byte[] aesKeyBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        byte[] encryptedAESKeyOAEP = new byte[]{20, 21, 22, 23, 24};
        String encodedEncryptedAESOAEP = "oaep_encrypted_key";

        when(storage.retrieveString(eq(KEY_ALIAS))).thenReturn(encodedEncryptedAESOAEP);
        base64Mock.when(() -> Base64.decode(encodedEncryptedAESOAEP, Base64.DEFAULT)).thenReturn(encryptedAESKeyOAEP);

        doReturn(aesKeyBytes).when(cryptoUtil).RSADecrypt(encryptedAESKeyOAEP);

        byte[] result = cryptoUtil.getAESKey();

        assertThat(result, is(aesKeyBytes));

        Mockito.verify(rsaPkcs1Cipher, never()).init(anyInt(), any(PrivateKey.class));
        Mockito.verify(rsaPkcs1Cipher, never()).doFinal(any(byte[].class));

        Mockito.verify(storage, never()).retrieveString(OLD_KEY_ALIAS);
    }

    @Test
    public void shouldRecognizeIncompatiblePaddingModeInExceptionChain() throws Exception {
        CryptoUtil cryptoUtil = newCryptoUtilSpy();

        String encodedEncryptedAES = "encrypted_key";
        byte[] encryptedAESBytes = new byte[]{5, 6, 7, 8};

        when(storage.retrieveString(eq(KEY_ALIAS))).thenReturn(encodedEncryptedAES);
        when(storage.retrieveString(eq(OLD_KEY_ALIAS))).thenReturn(null);
        base64Mock.when(() -> Base64.decode(encodedEncryptedAES, Base64.DEFAULT)).thenReturn(encryptedAESBytes);

        ProviderException rootCause = new ProviderException("Incompatible padding mode");
        IllegalBlockSizeException middleException = new IllegalBlockSizeException("Encryption failed");
        middleException.initCause(rootCause);
        IncompatibleDeviceException topException = new IncompatibleDeviceException(middleException);

        doThrow(topException).when(cryptoUtil).RSADecrypt(encryptedAESBytes);

        when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        KeyStore.PrivateKeyEntry mockKeyEntry = mock(KeyStore.PrivateKeyEntry.class);
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        when(mockKeyEntry.getPrivateKey()).thenReturn(mockPrivateKey);
        when(keyStore.getEntry(eq(KEY_ALIAS), nullable(KeyStore.ProtectionParameter.class)))
                .thenReturn(mockKeyEntry);

        byte[] aesKeyBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        when(rsaPkcs1Cipher.doFinal(encryptedAESBytes)).thenReturn(aesKeyBytes);

        byte[] encryptedAESKeyOAEP = new byte[]{20, 21, 22, 23};
        doReturn(encryptedAESKeyOAEP).when(cryptoUtil).RSAEncrypt(aesKeyBytes);
        String encodedOAEP = "oaep_key";
        base64Mock.when(() -> Base64.encode(encryptedAESKeyOAEP, Base64.DEFAULT))
                .thenReturn(encodedOAEP.getBytes(StandardCharsets.UTF_8));

        byte[] result = cryptoUtil.getAESKey();
        assertThat(result, is(aesKeyBytes));
        Mockito.verify(rsaPkcs1Cipher).doFinal(encryptedAESBytes);

    }

    @Test
    public void shouldAllowMultipleRetrievalsAfterMigration() throws Exception {

        CryptoUtil cryptoUtil = newCryptoUtilSpy();

        byte[] aesKeyBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        byte[] encryptedAESKeyPKCS1 = new byte[]{20, 21, 22, 23, 24};
        byte[] encryptedAESKeyOAEP = new byte[]{30, 31, 32, 33, 34};
        String encodedEncryptedAESPKCS1 = "pkcs1_encrypted_key";
        String encodedEncryptedAESOAEP = "oaep_encrypted_key";

        // First retrieval - migration happens, returns decrypted key
        when(storage.retrieveString(eq(KEY_ALIAS))).thenReturn(encodedEncryptedAESPKCS1);
        when(storage.retrieveString(eq(OLD_KEY_ALIAS))).thenReturn(null);
        base64Mock.when(() -> Base64.decode(encodedEncryptedAESPKCS1, Base64.DEFAULT)).thenReturn(encryptedAESKeyPKCS1);
        base64Mock.when(() -> Base64.encode(encryptedAESKeyOAEP, Base64.DEFAULT))
                .thenReturn(encodedEncryptedAESOAEP.getBytes(StandardCharsets.UTF_8));

        IncompatibleDeviceException incompatibleException = new IncompatibleDeviceException(
                new KeyStoreException("Incompatible padding mode")
        );
        doThrow(incompatibleException).when(cryptoUtil).RSADecrypt(encryptedAESKeyPKCS1);

        when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        KeyStore.PrivateKeyEntry mockKeyEntry = mock(KeyStore.PrivateKeyEntry.class);
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        Certificate mockCertificate = mock(Certificate.class);
        PublicKey mockPublicKey = mock(PublicKey.class);
        when(mockKeyEntry.getPrivateKey()).thenReturn(mockPrivateKey);
        when(mockKeyEntry.getCertificate()).thenReturn(mockCertificate);
        when(mockCertificate.getPublicKey()).thenReturn(mockPublicKey);
        when(keyStore.getEntry(eq(KEY_ALIAS), nullable(KeyStore.ProtectionParameter.class)))
                .thenReturn(mockKeyEntry);

        when(rsaPkcs1Cipher.doFinal(encryptedAESKeyPKCS1)).thenReturn(aesKeyBytes);

        // Mock RSAEncrypt for re-encrypting with OAEP after migration
        doReturn(encryptedAESKeyOAEP).when(cryptoUtil).RSAEncrypt(aesKeyBytes);

        byte[] result1 = cryptoUtil.getAESKey();
        assertThat(result1, is(aesKeyBytes));

        // Migration should delete old keys and store re-encrypted AES key
        Mockito.verify(keyStore).deleteEntry(KEY_ALIAS);
        Mockito.verify(storage).store(KEY_ALIAS, encodedEncryptedAESOAEP);
    }

    @Test
    public void shouldGenerateNewKeyWhenMigrationFails() throws Exception {
        CryptoUtil cryptoUtil = newCryptoUtilSpy();

        String encodedOldKey = "corrupted_old_key";
        byte[] encryptedOldKey = new byte[]{5, 6, 7};

        when(storage.retrieveString(eq(KEY_ALIAS))).thenReturn(null);
        when(storage.retrieveString(eq(OLD_KEY_ALIAS))).thenReturn(encodedOldKey);
        base64Mock.when(() -> Base64.decode(encodedOldKey, Base64.DEFAULT)).thenReturn(encryptedOldKey);

        doThrow(new CryptoException("Key corrupted", new KeyStoreException("Entry not found")))
                .when(cryptoUtil).getRSAKeyEntry();

        byte[] newAESKey = new byte[]{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36};
        SecretKey mockSecretKey = mock(SecretKey.class);
        when(mockSecretKey.getEncoded()).thenReturn(newAESKey);
        when(keyGenerator.generateKey()).thenReturn(mockSecretKey);

        byte[] encryptedNewKey = new byte[]{40, 41, 42};
        doReturn(encryptedNewKey).when(cryptoUtil).RSAEncrypt(any(byte[].class));
        String encodedNewKey = "fresh_key";
        base64Mock.when(() -> Base64.encode(encryptedNewKey, Base64.DEFAULT))
                .thenReturn(encodedNewKey.getBytes(StandardCharsets.UTF_8));
        byte[] result = cryptoUtil.getAESKey();
        assertThat(result, is(newAESKey));
        Mockito.verify(storage).store(KEY_ALIAS, encodedNewKey);
        // deleteAESKeys() is called once in tryMigrateLegacyAESKey when getRSAKeyEntry throws
        Mockito.verify(storage, times(1)).remove(KEY_ALIAS);
        Mockito.verify(storage, times(1)).remove(OLD_KEY_ALIAS);
    }

    /*
     * Helper methods
     */
    private CryptoUtil newCryptoUtilSpy() throws Exception {
        CryptoUtil cryptoUtil = Mockito.spy(new CryptoUtil(context, storage, BASE_ALIAS));
        Mockito.when(KeyStore.getInstance(ANDROID_KEY_STORE)).thenReturn(keyStore);
        Mockito.when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE)).thenReturn(keyPairGenerator);
        Mockito.when(KeyGenerator.getInstance(ALGORITHM_AES)).thenReturn(keyGenerator);
        Mockito.when(Cipher.getInstance(anyString())).then((Answer<Cipher>) invocation -> {
            String transformation = invocation.getArgument(0, String.class);
            if (RSA_TRANSFORMATION.equals(transformation)) {
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
}
