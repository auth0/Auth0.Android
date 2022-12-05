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
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.util.ReflectionHelpers;

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
import java.security.ProviderException;
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
import javax.security.auth.x500.X500Principal;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;

/**
 * In the rest of the test files we use Mockito as that's enough for most cases. However,
 * when Kotlin classes are introduced in the project, Mockito fails to mock them because
 * they are final by default.
 * The solution is to use the 'mockito-inline' plugin. However, when used in combination
 * with Powermock, both configuration files clash and the tests fail.
 * The MockMaker needs to be set up only in one place, the Powermock configuration file.
 * <p>
 * Read more: https://github.com/powermock/powermock/issues/992#issuecomment-662845804
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({CryptoUtil.class, KeyGenerator.class, TextUtils.class, Build.VERSION.class, Base64.class, Cipher.class, Log.class})
public class CryptoUtilTest {

    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NOPADDING";
    private static final String CERTIFICATE_PRINCIPAL = "CN=Auth0.Android,O=Auth0";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_RSA = "RSA";

    private final Storage storage = PowerMockito.mock(Storage.class);
    private final Cipher rsaCipher = PowerMockito.mock(Cipher.class);
    private final Cipher aesCipher = PowerMockito.mock(Cipher.class);
    private final KeyStore keyStore = PowerMockito.mock(KeyStore.class);
    private final KeyPairGenerator keyPairGenerator = PowerMockito.mock(KeyPairGenerator.class);
    private final KeyGenerator keyGenerator = PowerMockito.mock(KeyGenerator.class);

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
        PowerMockito.mockStatic(Log.class);
        PowerMockito.mockStatic(TextUtils.class);
        PowerMockito.when(TextUtils.isEmpty(anyString())).then((Answer<Boolean>) invocation -> {
            String input = invocation.getArgument(0, String.class);
            return input == null || input.isEmpty();
        });

        context = mock(Context.class);
        when(context.getPackageName()).thenReturn(APP_PACKAGE_NAME);
        cryptoUtil = newCryptoUtilSpy();
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
    @Config(sdk = 19)
    public void shouldNotCreateProtectedRSAKeyPairIfMissingAndLockScreenEnabledOnAPI19() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 19);

        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        KeyPairGeneratorSpec spec = PowerMockito.mock(KeyPairGeneratorSpec.class);
        KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(spec);
        PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);

        ArgumentCaptor<X500Principal> principalCaptor = ArgumentCaptor.forClass(X500Principal.class);
        ArgumentCaptor<Date> startDateCaptor = ArgumentCaptor.forClass(Date.class);
        ArgumentCaptor<Date> endDateCaptor = ArgumentCaptor.forClass(Date.class);

        //Set LockScreen as Enabled
        KeyguardManager kService = PowerMockito.mock(KeyguardManager.class);
        PowerMockito.when(context.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        PowerMockito.when(kService.isKeyguardSecure()).thenReturn(true);

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(builder).setKeySize(2048);
        Mockito.verify(builder).setSubject(principalCaptor.capture());
        Mockito.verify(builder).setAlias(KEY_ALIAS);
        Mockito.verify(builder).setSerialNumber(BigInteger.ONE);
        Mockito.verify(builder).setStartDate(startDateCaptor.capture());
        Mockito.verify(builder).setEndDate(endDateCaptor.capture());
        Mockito.verify(builder, never()).setEncryptionRequired();
        Mockito.verify(keyPairGenerator).initialize(spec);
        Mockito.verify(keyPairGenerator).generateKeyPair();

        assertThat(principalCaptor.getValue(), is(notNullValue()));
        assertThat(principalCaptor.getValue().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(startDateCaptor.getValue(), is(notNullValue()));
        long diffMillis = startDateCaptor.getValue().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(endDateCaptor.getValue(), is(notNullValue()));
        diffMillis = endDateCaptor.getValue().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 21)
    public void shouldCreateUnprotectedRSAKeyPairIfMissingAndLockScreenDisabledOnAPI21() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 21);

        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        KeyPairGeneratorSpec spec = PowerMockito.mock(KeyPairGeneratorSpec.class);
        KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(spec);
        PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);

        ArgumentCaptor<X500Principal> principalCaptor = ArgumentCaptor.forClass(X500Principal.class);
        ArgumentCaptor<Date> startDateCaptor = ArgumentCaptor.forClass(Date.class);
        ArgumentCaptor<Date> endDateCaptor = ArgumentCaptor.forClass(Date.class);

        //Set LockScreen as Disabled
        KeyguardManager kService = PowerMockito.mock(KeyguardManager.class);
        PowerMockito.when(context.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        PowerMockito.when(kService.isKeyguardSecure()).thenReturn(false);
        PowerMockito.when(kService.createConfirmDeviceCredentialIntent(any(CharSequence.class), any(CharSequence.class))).thenReturn(null);

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(builder).setKeySize(2048);
        Mockito.verify(builder).setSubject(principalCaptor.capture());
        Mockito.verify(builder).setAlias(KEY_ALIAS);
        Mockito.verify(builder).setSerialNumber(BigInteger.ONE);
        Mockito.verify(builder).setStartDate(startDateCaptor.capture());
        Mockito.verify(builder).setEndDate(endDateCaptor.capture());
        Mockito.verify(builder, never()).setEncryptionRequired();
        Mockito.verify(keyPairGenerator).initialize(spec);
        Mockito.verify(keyPairGenerator).generateKeyPair();

        assertThat(principalCaptor.getValue(), is(notNullValue()));
        assertThat(principalCaptor.getValue().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(startDateCaptor.getValue(), is(notNullValue()));
        long diffMillis = startDateCaptor.getValue().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(endDateCaptor.getValue(), is(notNullValue()));
        diffMillis = endDateCaptor.getValue().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 21)
    public void shouldCreateProtectedRSAKeyPairIfMissingAndLockScreenEnabledOnAPI21() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 21);

        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        KeyPairGeneratorSpec spec = PowerMockito.mock(KeyPairGeneratorSpec.class);
        KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(spec);
        PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);

        ArgumentCaptor<X500Principal> principalCaptor = ArgumentCaptor.forClass(X500Principal.class);
        ArgumentCaptor<Date> startDateCaptor = ArgumentCaptor.forClass(Date.class);
        ArgumentCaptor<Date> endDateCaptor = ArgumentCaptor.forClass(Date.class);

        //Set LockScreen as Enabled
        KeyguardManager kService = PowerMockito.mock(KeyguardManager.class);
        PowerMockito.when(context.getSystemService(Context.KEYGUARD_SERVICE)).thenReturn(kService);
        PowerMockito.when(kService.isKeyguardSecure()).thenReturn(true);
        PowerMockito.when(kService.createConfirmDeviceCredentialIntent(any(), any())).thenReturn(new Intent());

        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(builder).setKeySize(2048);
        Mockito.verify(builder).setSubject(principalCaptor.capture());
        Mockito.verify(builder).setAlias(KEY_ALIAS);
        Mockito.verify(builder).setSerialNumber(BigInteger.ONE);
        Mockito.verify(builder).setStartDate(startDateCaptor.capture());
        Mockito.verify(builder).setEndDate(endDateCaptor.capture());
        Mockito.verify(builder).setEncryptionRequired();
        Mockito.verify(keyPairGenerator).initialize(spec);
        Mockito.verify(keyPairGenerator).generateKeyPair();

        assertThat(principalCaptor.getValue(), is(notNullValue()));
        assertThat(principalCaptor.getValue().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(startDateCaptor.getValue(), is(notNullValue()));
        long diffMillis = startDateCaptor.getValue().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(endDateCaptor.getValue(), is(notNullValue()));
        diffMillis = endDateCaptor.getValue().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 23)
    public void shouldCreateRSAKeyPairIfMissingOnAPI23AndUp() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 23);

        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        KeyGenParameterSpec spec = PowerMockito.mock(KeyGenParameterSpec.class);
        KeyGenParameterSpec.Builder builder = newKeyGenParameterSpecBuilder(spec);
        PowerMockito.whenNew(KeyGenParameterSpec.Builder.class).withArguments(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT).thenReturn(builder);

        ArgumentCaptor<X500Principal> principalCaptor = ArgumentCaptor.forClass(X500Principal.class);
        ArgumentCaptor<Date> startDateCaptor = ArgumentCaptor.forClass(Date.class);
        ArgumentCaptor<Date> endDateCaptor = ArgumentCaptor.forClass(Date.class);


        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();


        Mockito.verify(builder).setKeySize(2048);
        Mockito.verify(builder).setCertificateSubject(principalCaptor.capture());
        Mockito.verify(builder).setCertificateSerialNumber(BigInteger.ONE);
        Mockito.verify(builder).setCertificateNotBefore(startDateCaptor.capture());
        Mockito.verify(builder).setCertificateNotAfter(endDateCaptor.capture());
        Mockito.verify(builder).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        Mockito.verify(builder).setBlockModes(KeyProperties.BLOCK_MODE_ECB);
        Mockito.verify(keyPairGenerator).initialize(spec);
        Mockito.verify(keyPairGenerator).generateKeyPair();

        assertThat(principalCaptor.getValue(), is(notNullValue()));
        assertThat(principalCaptor.getValue().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(startDateCaptor.getValue(), is(notNullValue()));
        long diffMillis = startDateCaptor.getValue().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(endDateCaptor.getValue(), is(notNullValue()));
        diffMillis = endDateCaptor.getValue().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldCreateRSAKeyPairIfMissingOnAPI28AndUp() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);

        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
        KeyStore.PrivateKeyEntry expectedEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        KeyGenParameterSpec spec = PowerMockito.mock(KeyGenParameterSpec.class);
        KeyGenParameterSpec.Builder builder = newKeyGenParameterSpecBuilder(spec);
        PowerMockito.whenNew(KeyGenParameterSpec.Builder.class).withArguments(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT).thenReturn(builder);

        ArgumentCaptor<X500Principal> principalCaptor = ArgumentCaptor.forClass(X500Principal.class);
        ArgumentCaptor<Date> startDateCaptor = ArgumentCaptor.forClass(Date.class);
        ArgumentCaptor<Date> endDateCaptor = ArgumentCaptor.forClass(Date.class);


        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(builder).setKeySize(2048);
        Mockito.verify(builder).setCertificateSubject(principalCaptor.capture());
        Mockito.verify(builder).setCertificateSerialNumber(BigInteger.ONE);
        Mockito.verify(builder).setCertificateNotBefore(startDateCaptor.capture());
        Mockito.verify(builder).setCertificateNotAfter(endDateCaptor.capture());
        Mockito.verify(builder).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        Mockito.verify(builder).setBlockModes(KeyProperties.BLOCK_MODE_ECB);
        Mockito.verify(keyPairGenerator).initialize(spec);
        Mockito.verify(keyPairGenerator).generateKeyPair();

        assertThat(principalCaptor.getValue(), is(notNullValue()));
        assertThat(principalCaptor.getValue().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(startDateCaptor.getValue(), is(notNullValue()));
        long diffMillis = startDateCaptor.getValue().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(endDateCaptor.getValue(), is(notNullValue()));
        diffMillis = endDateCaptor.getValue().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldCreateNewRSAKeyPairWhenExistingRSAKeyPairCannotBeRebuiltOnAPI28AndUp() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);
        PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);

        //This is required to trigger the fallback when alias is present but key is not
        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        PowerMockito.when(keyStore.getKey(KEY_ALIAS, null)).thenReturn(privateKey).thenReturn(null);
        PowerMockito.when(keyStore.getCertificate(KEY_ALIAS)).thenReturn(null);
        //This is required to trigger finding the key after generating it
        KeyStore.PrivateKeyEntry expectedEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(expectedEntry);

        //Tests no instantiation of PrivateKeyEntry
        PowerMockito.verifyZeroInteractions(KeyStore.PrivateKeyEntry.class);

        //Creation assertion
        KeyGenParameterSpec spec = PowerMockito.mock(KeyGenParameterSpec.class);
        KeyGenParameterSpec.Builder builder = newKeyGenParameterSpecBuilder(spec);
        PowerMockito.whenNew(KeyGenParameterSpec.Builder.class).withArguments(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT).thenReturn(builder);

        ArgumentCaptor<X500Principal> principalCaptor = ArgumentCaptor.forClass(X500Principal.class);
        ArgumentCaptor<Date> startDateCaptor = ArgumentCaptor.forClass(Date.class);
        ArgumentCaptor<Date> endDateCaptor = ArgumentCaptor.forClass(Date.class);


        final KeyStore.PrivateKeyEntry entry = cryptoUtil.getRSAKeyEntry();

        Mockito.verify(builder).setKeySize(2048);
        Mockito.verify(builder).setCertificateSubject(principalCaptor.capture());
        Mockito.verify(builder).setCertificateSerialNumber(BigInteger.ONE);
        Mockito.verify(builder).setCertificateNotBefore(startDateCaptor.capture());
        Mockito.verify(builder).setCertificateNotAfter(endDateCaptor.capture());
        Mockito.verify(builder).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        Mockito.verify(builder).setBlockModes(KeyProperties.BLOCK_MODE_ECB);
        Mockito.verify(keyPairGenerator).initialize(spec);
        Mockito.verify(keyPairGenerator).generateKeyPair();

        assertThat(principalCaptor.getValue(), is(notNullValue()));
        assertThat(principalCaptor.getValue().getName(), is(CERTIFICATE_PRINCIPAL));

        assertThat(startDateCaptor.getValue(), is(notNullValue()));
        long diffMillis = startDateCaptor.getValue().getTime() - new Date().getTime();
        long days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(0L)); //Date is Today

        assertThat(endDateCaptor.getValue(), is(notNullValue()));
        diffMillis = endDateCaptor.getValue().getTime() - new Date().getTime();
        days = TimeUnit.MILLISECONDS.toDays(diffMillis);
        assertThat(days, is(greaterThan(25 * 365L))); //Date more than 25 Years in days

        assertThat(entry, is(expectedEntry));
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingRSAKeyPairRebuildingTheEntryOnAPI28AndUp() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);
        KeyStore.PrivateKeyEntry entry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
        Certificate certificate = PowerMockito.mock(Certificate.class);

        ArgumentCaptor<Object> varargsCaptor = ArgumentCaptor.forClass(Object.class);
        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        PowerMockito.when(keyStore.getKey(KEY_ALIAS, null)).thenReturn(privateKey);
        PowerMockito.when(keyStore.getCertificate(KEY_ALIAS)).thenReturn(certificate);
        PowerMockito.whenNew(KeyStore.PrivateKeyEntry.class).withAnyArguments().thenReturn(entry);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        PowerMockito.verifyNew(KeyStore.PrivateKeyEntry.class).withArguments(varargsCaptor.capture());
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(entry));
        assertThat(varargsCaptor.getAllValues(), is(notNullValue()));
        PrivateKey capturedPrivateKey = (PrivateKey) varargsCaptor.getAllValues().get(0);
        Certificate[] capturedCertificatesArray = (Certificate[]) varargsCaptor.getAllValues().get(1);
        assertThat(capturedPrivateKey, is(privateKey));
        assertThat(capturedCertificatesArray[0], is(certificate));
        assertThat(capturedCertificatesArray.length, is(1));
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingPrivateKeyForOldKeyAlias() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);
        KeyStore.PrivateKeyEntry entry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
        Certificate certificate = PowerMockito.mock(Certificate.class);

        KeyGenParameterSpec.Builder builder = PowerMockito.mock(KeyGenParameterSpec.Builder.class);
        PowerMockito.when(builder.setKeySize(anyInt())).thenReturn(builder);
        PowerMockito.when(builder.setCertificateSubject(any(X500Principal.class))).thenReturn(builder);

        ArgumentCaptor<Object> varargsCaptor = ArgumentCaptor.forClass(Object.class);
        PowerMockito.when(keyStore.containsAlias(OLD_KEY_ALIAS)).thenReturn(true);
        PowerMockito.when(keyStore.getKey(OLD_KEY_ALIAS, null)).thenReturn(privateKey);
        PowerMockito.when(keyStore.getCertificate(OLD_KEY_ALIAS)).thenReturn(certificate);
        PowerMockito.whenNew(KeyStore.PrivateKeyEntry.class).withAnyArguments().thenReturn(entry);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        PowerMockito.verifyNew(KeyStore.PrivateKeyEntry.class).withArguments(varargsCaptor.capture());
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(entry));
        assertThat(varargsCaptor.getAllValues(), is(notNullValue()));
        PrivateKey capturedPrivateKey = (PrivateKey) varargsCaptor.getAllValues().get(0);
        Certificate[] capturedCertificatesArray = (Certificate[]) varargsCaptor.getAllValues().get(1);
        assertThat(capturedPrivateKey, is(privateKey));
        assertThat(capturedCertificatesArray[0], is(certificate));
        assertThat(capturedCertificatesArray.length, is(1));
    }

    @Test
    @Config(sdk = 28)
    public void shouldUseExistingRSAKeyPairOnAPI28AndUp() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 28);
        KeyStore.PrivateKeyEntry entry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(entry);
        PrivateKey privateKey = null;
        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        PowerMockito.when(keyStore.getKey(KEY_ALIAS, null)).thenReturn(privateKey);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(entry));
    }

    @Test
    @Config(sdk = 27)
    public void shouldUseExistingRSAKeyPairOnAPI27AndDown() throws Exception {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 27);
        KeyStore.PrivateKeyEntry entry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
        PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null)).thenReturn(entry);

        KeyStore.PrivateKeyEntry rsaEntry = cryptoUtil.getRSAKeyEntry();
        assertThat(rsaEntry, is(notNullValue()));
        assertThat(rsaEntry, is(entry));
    }

    @Test
    public void shouldDeleteRSAAndAESKeysAndThrowOnUnrecoverableEntryExceptionWhenTryingToObtainRSAKeys() throws Exception {
        Assert.assertThrows("The existing RSA key pair could not be recovered and has been deleted. " +
                "This occasionally happens when the Lock Screen settings are changed. You can safely retry this operation.", CryptoException.class, () -> {
            KeyStore.PrivateKeyEntry entry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(true);
            PowerMockito.when(keyStore.getEntry(KEY_ALIAS, null))
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
            PowerMockito.mockStatic(KeyStore.class);
            PowerMockito.when(KeyStore.getInstance(anyString()))
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
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 19);
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
            KeyPairGeneratorSpec spec = PowerMockito.mock(KeyPairGeneratorSpec.class);
            KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(spec);
            PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);

            PowerMockito.mockStatic(KeyPairGenerator.class);
            PowerMockito.when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE))
                    .thenThrow(new NoSuchProviderException());

            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToObtainRSAKeys() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 19);
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
            KeyPairGeneratorSpec spec = PowerMockito.mock(KeyPairGeneratorSpec.class);
            KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(spec);
            PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);

            PowerMockito.mockStatic(KeyPairGenerator.class);
            PowerMockito.when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE))
                    .thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.getRSAKeyEntry();
        });
    }

    @Test
    public void shouldThrowOnInvalidAlgorithmParameterExceptionWhenTryingToObtainRSAKeys() {
        ReflectionHelpers.setStaticField(Build.VERSION.class, "SDK_INT", 19);
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PowerMockito.when(keyStore.containsAlias(KEY_ALIAS)).thenReturn(false);
            KeyPairGeneratorSpec spec = PowerMockito.mock(KeyPairGeneratorSpec.class);
            KeyPairGeneratorSpec.Builder builder = newKeyPairGeneratorSpecBuilder(spec);
            PowerMockito.whenNew(KeyPairGeneratorSpec.Builder.class).withAnyArguments().thenReturn(builder);

            doThrow(new InvalidAlgorithmParameterException()).when(keyPairGenerator).initialize(any(AlgorithmParameterSpec.class));

            cryptoUtil.getRSAKeyEntry();
        });
    }

    /*
     * GET AES KEY tests
     */

    @Test
    public void shouldCreateAESKeyIfMissing() {
        byte[] sampleBytes = new byte[]{0, 1, 2, 3, 4, 5};
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.encode(sampleBytes, Base64.DEFAULT)).thenReturn("data".getBytes());
        PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(null);

        SecretKey secretKey = PowerMockito.mock(SecretKey.class);
        PowerMockito.when(keyGenerator.generateKey()).thenReturn(secretKey);
        PowerMockito.when(secretKey.getEncoded()).thenReturn(sampleBytes);
        doReturn(sampleBytes).when(cryptoUtil).RSAEncrypt(sampleBytes);


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
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.decode(emptyString, Base64.DEFAULT)).thenReturn(sampleBytes);
        PowerMockito.when(Base64.encode(sampleBytes, Base64.DEFAULT)).thenReturn("data".getBytes());
        PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(emptyString);
        doReturn(sampleBytes).when(cryptoUtil).RSAEncrypt(sampleBytes);

        //Assume RSAKeyEntry exists
        PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
        KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
        doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        doReturn(sampleOutput).when(rsaCipher).doFinal(sampleBytes);

        SecretKey secretKey = PowerMockito.mock(SecretKey.class);
        PowerMockito.when(secretKey.getEncoded()).thenReturn(sampleBytes);
        PowerMockito.when(keyGenerator.generateKey()).thenReturn(secretKey);


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

        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.decode(aesString, Base64.DEFAULT)).thenReturn(sampleBytes);
        PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(aesString);
        doReturn(sampleBytes).when(cryptoUtil).RSADecrypt(sampleBytes);

        final byte[] aesKey = cryptoUtil.getAESKey();
        assertThat(aesKey, is(notNullValue()));
        assertThat(aesKey, is(sampleBytes));
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenCreatingAESKey() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn(null);
            PowerMockito.mockStatic(KeyGenerator.class);
            PowerMockito.when(KeyGenerator.getInstance(ALGORITHM_AES))
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

        Certificate certificate = PowerMockito.mock(Certificate.class);
        KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        doReturn(certificate).when(privateKeyEntry).getCertificate();
        doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        doReturn(sampleOutput).when(rsaCipher).doFinal(sampleInput);

        final byte[] output = cryptoUtil.RSAEncrypt(sampleInput);

        Mockito.verify(rsaCipher).init(Cipher.ENCRYPT_MODE, certificate);
        assertThat(output, is(sampleOutput));
    }

    @Test
    public void shouldThrowOnInvalidKeyExceptionWhenTryingToRSAEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            byte[] sampleBytes = new byte[0];
            Certificate certificate = PowerMockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaCipher);
            doThrow(new InvalidKeyException()).when(rsaCipher).init(Cipher.ENCRYPT_MODE, certificate);

            cryptoUtil.RSAEncrypt(sampleBytes);
        });
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnBadPaddingExceptionWhenTryingToRSAEncrypt() throws Exception {
        Assert.assertThrows("The RSA decrypted input is invalid.", CryptoException.class, () -> {

            byte[] sampleBytes = new byte[0];
            Certificate certificate = PowerMockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaCipher);
            PowerMockito.when(rsaCipher.doFinal(sampleBytes)).thenThrow(new BadPaddingException());

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
            Certificate certificate = PowerMockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaCipher);
            PowerMockito.when(rsaCipher.doFinal(any(byte[].class))).thenThrow(new IllegalBlockSizeException());

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
            Certificate certificate = PowerMockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.RSAEncrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToRSAEncrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            Certificate certificate = PowerMockito.mock(Certificate.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(certificate).when(privateKeyEntry).getCertificate();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

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

        PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
        KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
        doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
        doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
        doReturn(sampleOutput).when(rsaCipher).doFinal(sampleInput);

        final byte[] output = cryptoUtil.RSADecrypt(sampleInput);

        Mockito.verify(rsaCipher).init(Cipher.DECRYPT_MODE, privateKey);
        assertThat(output, is(sampleOutput));
    }

    @Test
    public void shouldThrowOnInvalidKeyExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            byte[] sampleBytes = new byte[0];
            PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenReturn(rsaCipher);
            doThrow(new InvalidKeyException()).when(rsaCipher).init(Cipher.DECRYPT_MODE, privateKey);

            cryptoUtil.RSADecrypt(sampleBytes);
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.RSADecrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchPaddingExceptionWhenTryingToRSADecrypt() {
        Assert.assertThrows("The device is not compatible with the CryptoUtil class", IncompatibleDeviceException.class, () -> {
            PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(RSA_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

            cryptoUtil.RSADecrypt(new byte[0]);
        });
    }

    @Test
    public void shouldDeleteAESKeysAndThrowOnBadPaddingExceptionWhenTryingToRSADecrypt() throws Exception {
        Assert.assertThrows("The RSA encrypted input is corrupted and cannot be recovered. Please discard it.", CryptoException.class, () -> {
            PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();

            doThrow(new BadPaddingException()).when(rsaCipher).doFinal(any(byte[].class));
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
            PrivateKey privateKey = PowerMockito.mock(PrivateKey.class);
            KeyStore.PrivateKeyEntry privateKeyEntry = PowerMockito.mock(KeyStore.PrivateKeyEntry.class);
            doReturn(privateKey).when(privateKeyEntry).getPrivateKey();
            doReturn(privateKeyEntry).when(cryptoUtil).getRSAKeyEntry();

            doThrow(new IllegalBlockSizeException()).when(rsaCipher).doFinal(any(byte[].class));
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
        byte[] iv = new byte[]{99, 99, 11, 11};
        byte[] encodedIv = "iv-data".getBytes();

        doReturn(aesKey).when(cryptoUtil).getAESKey();
        doReturn(encryptedData).when(aesCipher).doFinal(data);
        PowerMockito.when(aesCipher.doFinal(data)).thenReturn(encryptedData);
        PowerMockito.when(aesCipher.getIV()).thenReturn(iv);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.encode(iv, Base64.DEFAULT)).thenReturn(encodedIv);

        final byte[] encrypted = cryptoUtil.encrypt(data);


        Mockito.verify(aesCipher).init(eq(Cipher.ENCRYPT_MODE), secretKeyCaptor.capture());
        assertThat(secretKeyCaptor.getValue(), is(notNullValue()));
        assertThat(secretKeyCaptor.getValue().getAlgorithm(), is(ALGORITHM_AES));
        assertThat(secretKeyCaptor.getValue().getEncoded(), is(aesKey));

        Mockito.verify(storage).store(KEY_ALIAS + "_iv", "iv-data");
        assertThat(encrypted, is(encryptedData));
    }

    @Test
    public void shouldThrowOnCryptoExceptionOnRSAKeyReadingWhenTryingToAESEncrypt() {
        Assert.assertThrows(CryptoException.class, () -> {
            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

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
            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

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

            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

            cryptoUtil.encrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToAESEncrypt() throws Exception {
        Assert.assertThrows(IncompatibleDeviceException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();

            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

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

            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
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
     * MAIN DECRYPT (AES) tests
     */

    @Test
    public void shouldAESDecryptData() throws Exception {
        ArgumentCaptor<SecretKey> secretKeyCaptor = ArgumentCaptor.forClass(SecretKey.class);
        ArgumentCaptor<IvParameterSpec> ivParameterSpecCaptor = ArgumentCaptor.forClass(IvParameterSpec.class);
        byte[] aesKey = "aes-decrypted-key".getBytes();
        byte[] data = "data".getBytes();
        byte[] decryptedData = new byte[]{0, 1, 2, 3, 4, 5};
        String encodedIv = "iv-data";

        doReturn(aesKey).when(cryptoUtil).getAESKey();
        doReturn(decryptedData).when(aesCipher).doFinal(data);
        PowerMockito.when(aesCipher.doFinal(data)).thenReturn(decryptedData);
        PowerMockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn(encodedIv);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.decode(encodedIv, Base64.DEFAULT)).thenReturn(encodedIv.getBytes());

        final byte[] decrypted = cryptoUtil.decrypt(data);


        Mockito.verify(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyCaptor.capture(), ivParameterSpecCaptor.capture());
        assertThat(secretKeyCaptor.getValue(), is(notNullValue()));
        assertThat(secretKeyCaptor.getValue().getAlgorithm(), is(ALGORITHM_AES));
        assertThat(secretKeyCaptor.getValue().getEncoded(), is(aesKey));
        assertThat(ivParameterSpecCaptor.getValue(), is(notNullValue()));
        assertThat(ivParameterSpecCaptor.getValue().getIV(), is(encodedIv.getBytes()));

        assertThat(decrypted, is(decryptedData));
    }

    @Test
    public void shouldThrowOnCryptoExceptionOnRSAKeyReadingWhenTryingToAESDecrypt() {
        Assert.assertThrows(CryptoException.class, () -> {
            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

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
            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("encoded-key", Base64.DEFAULT)).thenReturn(new byte[0]);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS)).thenReturn("encoded-key");

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

            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchPaddingException());

            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnNoSuchAlgorithmExceptionWhenTryingToAESDecrypt() {
        Assert.assertThrows(IncompatibleDeviceException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();

            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenThrow(new NoSuchAlgorithmException());

            cryptoUtil.decrypt(new byte[0]);
        });
    }

    @Test
    public void shouldThrowOnEmptyInitializationVectorWhenTryingToAESDecrypt() {
        Assert.assertThrows("The encryption keys changed recently. You need to re-encrypt something first.", CryptoException.class, () -> {
            doReturn(new byte[]{11, 22, 33}).when(cryptoUtil).getAESKey();
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("");
            PowerMockito.when(storage.retrieveString(BASE_ALIAS + "_iv")).thenReturn("");

            cryptoUtil.decrypt(new byte[0]);
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
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new InvalidKeyException()).when(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyArgumentCaptor.capture(), ivParameterSpecArgumentCaptor.capture());

            cryptoUtil.decrypt(new byte[0]);
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
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new InvalidAlgorithmParameterException()).when(aesCipher).init(eq(Cipher.DECRYPT_MODE), secretKeyArgumentCaptor.capture(), ivParameterSpecArgumentCaptor.capture());
            cryptoUtil.decrypt(new byte[0]);
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
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new BadPaddingException()).when(aesCipher).doFinal(any(byte[].class));

            cryptoUtil.decrypt(new byte[0]);
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
            PowerMockito.mockStatic(Cipher.class);
            PowerMockito.when(Cipher.getInstance(AES_TRANSFORMATION)).thenReturn(aesCipher);
            PowerMockito.when(storage.retrieveString(KEY_ALIAS + "_iv")).thenReturn("a_valid_iv");

            byte[] ivBytes = new byte[]{99, 22};
            PowerMockito.mockStatic(Base64.class);
            PowerMockito.when(Base64.decode("a_valid_iv", Base64.DEFAULT)).thenReturn(ivBytes);

            doThrow(new IllegalBlockSizeException()).when(aesCipher).doFinal(any(byte[].class));

            cryptoUtil.decrypt(new byte[0]);
        });

        Mockito.verify(keyStore, never()).deleteEntry(KEY_ALIAS);
        Mockito.verify(keyStore, never()).deleteEntry(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS);
        Mockito.verify(storage, never()).remove(KEY_ALIAS + "_iv");
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS);
        Mockito.verify(storage, never()).remove(OLD_KEY_ALIAS + "_iv");
    }


    /*
     * Helper methods
     */
    private KeyPairGeneratorSpec.Builder newKeyPairGeneratorSpecBuilder(KeyPairGeneratorSpec expectedBuilderOutput) {
        KeyPairGeneratorSpec.Builder builder = PowerMockito.mock(KeyPairGeneratorSpec.Builder.class);
        PowerMockito.when(builder.setAlias(anyString())).thenReturn(builder);
        PowerMockito.when(builder.setSubject(any(X500Principal.class))).thenReturn(builder);
        PowerMockito.when(builder.setKeySize(anyInt())).thenReturn(builder);
        PowerMockito.when(builder.setSerialNumber(any(BigInteger.class))).thenReturn(builder);
        PowerMockito.when(builder.setStartDate(any(Date.class))).thenReturn(builder);
        PowerMockito.when(builder.setEndDate(any(Date.class))).thenReturn(builder);
        PowerMockito.when(builder.setEncryptionRequired()).thenReturn(builder);
        PowerMockito.when(builder.build()).thenReturn(expectedBuilderOutput);
        return builder;
    }

    private KeyGenParameterSpec.Builder newKeyGenParameterSpecBuilder(KeyGenParameterSpec expectedBuilderOutput) {
        KeyGenParameterSpec.Builder builder = PowerMockito.mock(KeyGenParameterSpec.Builder.class);
        PowerMockito.when(builder.setKeySize(anyInt())).thenReturn(builder);
        PowerMockito.when(builder.setCertificateSubject(any(X500Principal.class))).thenReturn(builder);
        PowerMockito.when(builder.setCertificateSerialNumber(any(BigInteger.class))).thenReturn(builder);
        PowerMockito.when(builder.setCertificateNotBefore(any(Date.class))).thenReturn(builder);
        PowerMockito.when(builder.setCertificateNotAfter(any(Date.class))).thenReturn(builder);
        //noinspection WrongConstant
        PowerMockito.when(builder.setEncryptionPaddings(anyString())).thenReturn(builder);
        //noinspection WrongConstant
        PowerMockito.when(builder.setBlockModes(anyString())).thenReturn(builder);
        PowerMockito.when(builder.build()).thenReturn(expectedBuilderOutput);
        return builder;
    }

    private CryptoUtil newCryptoUtilSpy() throws Exception {
        CryptoUtil cryptoUtil = PowerMockito.spy(new CryptoUtil(context, storage, BASE_ALIAS));
        PowerMockito.mockStatic(KeyStore.class);
        PowerMockito.when(KeyStore.getInstance(ANDROID_KEY_STORE)).thenReturn(keyStore);
        PowerMockito.mockStatic(KeyPairGenerator.class);
        PowerMockito.when(KeyPairGenerator.getInstance(ALGORITHM_RSA, ANDROID_KEY_STORE)).thenReturn(keyPairGenerator);
        PowerMockito.mockStatic(KeyGenerator.class);
        PowerMockito.when(KeyGenerator.getInstance(ALGORITHM_AES)).thenReturn(keyGenerator);
        PowerMockito.mockStatic(Cipher.class);
        PowerMockito.when(Cipher.getInstance(anyString())).then((Answer<Cipher>) invocation -> {
            String transformation = invocation.getArgument(0, String.class);
            if (RSA_TRANSFORMATION.equals(transformation)) {
                return rsaCipher;
            } else if (AES_TRANSFORMATION.equals(transformation)) {
                return aesCipher;
            }
            return null;
        });
        return cryptoUtil;
    }
}
