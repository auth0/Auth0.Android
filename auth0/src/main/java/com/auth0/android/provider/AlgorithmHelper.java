package com.auth0.android.provider;

import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class AlgorithmHelper {

    private static final String TAG = AlgorithmHelper.class.getSimpleName();

    private static final String SHA_256 = "SHA-256";

    private String getBase64String(byte[] source) {
        return Base64.encodeToString(source, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    byte[] getASCIIBytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    byte[] getSHA256(byte[] input) {
        byte[] signature;
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            md.update(input, 0, input.length);
            signature = md.digest();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to get SHA-256 signature", e);
            throw new IllegalStateException("Failed to get SHA-256 signature", e);
        }
        return signature;
    }

    String generateCodeVerifier() {
        SecureRandom sr = new SecureRandom();
        byte[] code = new byte[32];
        sr.nextBytes(code);
        return Base64.encodeToString(code, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    String generateCodeChallenge(@NonNull String codeVerifier) {
        byte[] input = getASCIIBytes(codeVerifier);
        byte[] signature = getSHA256(input);
        return getBase64String(signature);
    }
}