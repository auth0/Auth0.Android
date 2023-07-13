package com.auth0.android.provider;

import android.util.Base64;

import androidx.annotation.NonNull;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class JwtTestUtils {

    static final long FIXED_CLOCK_CURRENT_TIME_MS = 1567314000000L;
    static final String EXPECTED_BASE_DOMAIN = "test.domain.com";
    static final String EXPECTED_ISSUER = "https://" + EXPECTED_BASE_DOMAIN + "/";
    static final String[] EXPECTED_AUDIENCE_ARRAY = new String[]{"__test_client_id__", "__test_other_client_id__"};
    static final String EXPECTED_AUDIENCE = "__test_client_id__";
    static final String EXPECTED_NONCE = "__test_nonce__";
    static final String EXPECTED_ORGANIZATION_ID = "__test_org_id__";
    static final String EXPECTED_ORGANIZATION_NAME = "org___test_org_name__";
    static final Object EXPECTED_SUBJECT = "__test_subject__";

    private static final String RSA_PRIVATE_KEY = "src/test/resources/rsa_private.pem";
    private static final String RSA_PUBLIC_KEY = "src/test/resources/rsa_public.pem";

    public static String createTestJWT(@NonNull String algorithm, @NonNull Map<String, Object> bodyClaims) throws Exception {
        String header = "{" +
                "\"alg\":\"" + algorithm + "\"," +
                "\"typ\":\"JWT\"," +
                "\"kid\":\"key123\"" +
                "}";

        StringBuilder payloadBuilder = new StringBuilder("{");
        Iterator<Map.Entry<String, Object>> cIt = bodyClaims.entrySet().iterator();
        while (cIt.hasNext()) {
            Map.Entry<String, Object> c = cIt.next();
            String name = c.getKey();
            payloadBuilder.append("\"").append(name).append("\":");
            Object value = c.getValue();

            if (value instanceof String) {
                payloadBuilder.append("\"").append(value).append("\"");
            } else if (value instanceof Number) {
                payloadBuilder.append(((Number) value).longValue());
            } else if (value instanceof String[]) {
                String[] stringArr = (String[]) value;
                payloadBuilder.append("[");
                for (int k = 0; k < stringArr.length; k++) {
                    payloadBuilder.append("\"").append(stringArr[k]).append("\"");
                    if (k < stringArr.length - 1) {
                        payloadBuilder.append(",");
                    }
                }
                payloadBuilder.append("]");
            }

            if (cIt.hasNext()) {
                payloadBuilder.append(",");
            }
        }
        String body = payloadBuilder.append("}").toString();

        return signJWT(algorithm, header, body);
    }

    static Map<String, Object> createJWTBody(String... claimToRemove) {
        Map<String, Object> bodyClaims = new HashMap<>();
        long iat = FIXED_CLOCK_CURRENT_TIME_MS / 1000;
        long exp = iat + 3600;
        bodyClaims.put("iss", EXPECTED_ISSUER);
        bodyClaims.put("sub", EXPECTED_SUBJECT);
        bodyClaims.put("aud", EXPECTED_AUDIENCE);
        bodyClaims.put("nonce", EXPECTED_NONCE);
        bodyClaims.put("exp", exp);
        bodyClaims.put("iat", iat);
        if (claimToRemove != null) {
            for (String c : claimToRemove) {
                bodyClaims.remove(c);
            }
        }
        return bodyClaims;
    }

    private static String signJWT(@NonNull String algorithm, @NonNull String decodedHeader, @NonNull String decodedBody) throws Exception {
        if (!Arrays.asList("HS256", "RS256", "none").contains(algorithm)) {
            throw new IllegalArgumentException("[Unit Tests] ID token algorithm not supported");
        }

        byte[] encodedHeaderBytes = Base64.encode(decodedHeader.getBytes(), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        byte[] encodedBodyBytes = Base64.encode(decodedBody.getBytes(), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

        String signature = "";
        if (algorithm.equals("HS256")) {
            signature = "signature";
        } else if (algorithm.equals("RS256")) {
            PrivateKey pk = getPrivateKey();
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(pk);
            s.update(encodedHeaderBytes);
            s.update((byte) '.');
            s.update(encodedBodyBytes);
            byte[] signatureBytes = s.sign();
            signature = Base64.encodeToString(signatureBytes, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        }
        String encodedHeader = new String(encodedHeaderBytes, StandardCharsets.UTF_8);
        String encodedBody = new String(encodedBodyBytes, StandardCharsets.UTF_8);

        return String.format("%s.%s.%s", encodedHeader, encodedBody, signature);
    }

    static PrivateKey getPrivateKey() throws Exception {
        File f = new File(RSA_PRIVATE_KEY);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes, StandardCharsets.UTF_8);
        String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");

        byte[] decoded = Base64.decode(privKeyPEM, Base64.DEFAULT);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }


    static PublicKey getPublicKey() throws Exception {
        File f = new File(RSA_PUBLIC_KEY);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes, StandardCharsets.UTF_8);
        String pubKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----", "");
        pubKeyPEM = pubKeyPEM.replace("-----END PUBLIC KEY-----", "");

        byte[] decoded = Base64.decode(pubKeyPEM, Base64.DEFAULT);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
