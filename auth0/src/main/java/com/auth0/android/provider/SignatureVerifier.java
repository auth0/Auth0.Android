package com.auth0.android.provider;

import android.support.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.JWT;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Map;

/**
 * Abstract class meant to verify tokens signed with HS256 and RS256 signatures.
 */
abstract class SignatureVerifier {

    /**
     * Verifies that the given token's signature is valid, deeming the payload inside it authentic
     *
     * @param token the ID token to have its signature validated
     * @throws TokenValidationException if the signature is not valid
     */
    abstract void verifySignature(@NonNull JWT token) throws TokenValidationException;

    /**
     * Validates the algorithm of the given token is supported and creates a new instance of a SignatureVerifier
     *
     * @param token     the ID token to create a signature verifier for
     * @param apiClient api client instance to fetch the JWKS keys, if necessary
     * @param callback  the callback to receive the result in
     */
    static void forToken(@NonNull JWT token, @NonNull AuthenticationAPIClient apiClient, @NonNull final BaseCallback<SignatureVerifier, TokenValidationException> callback) {
        String algorithmName = token.getHeader().get("alg");
        if ("RS256".equals(algorithmName)) {
            final String keyId = token.getHeader().get("kid");
            apiClient.fetchJsonWebKeys().start(new AuthenticationCallback<Map<String, PublicKey>>() {
                @Override
                public void onSuccess(Map<String, PublicKey> jwks) {
                    PublicKey publicKey = jwks.get(keyId);
                    try {
                        callback.onSuccess(new AsymmetricSignatureVerifier(publicKey));
                    } catch (InvalidKeyException e) {
                        callback.onFailure(new TokenValidationException(String.format("Could not find a public key for kid \"%s\"", keyId)));
                    }
                }

                @Override
                public void onFailure(AuthenticationException error) {
                    callback.onFailure(new TokenValidationException(String.format("Could not find a public key for kid \"%s\"", keyId)));
                }
            });
        } else if ("HS256".equals(algorithmName)) {
            callback.onSuccess(new SymmetricSignatureVerifier());
        } else {
            callback.onFailure(new TokenValidationException(String.format("Signature algorithm of \"%s\" is not supported. Expected either \"RS256\" or \"HS256\".", algorithmName)));
        }
    }

}
