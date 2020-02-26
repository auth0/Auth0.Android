package com.auth0.android.provider;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.JWT;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;

/**
 * Abstract class meant to verify tokens signed with HS256 and RS256 signatures.
 */
abstract class SignatureVerifier {

    private final List<String> supportedAlgorithms;

    SignatureVerifier(List<String> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

    /**
     * Verifies that the given token's signature is valid, deeming the payload inside it authentic
     *
     * @param token the ID token to have its signature validated
     * @throws TokenValidationException if the signature is not valid
     */
    void verify(@NonNull JWT token) throws TokenValidationException {
        String tokenAlg = token.getHeader().get("alg");
        String[] tokenParts = token.toString().split("\\.");

        checkAlgorithm(tokenAlg);
        checkSignature(tokenParts);
    }

    private void checkAlgorithm(String tokenAlgorithm) throws TokenValidationException {
        if (!supportedAlgorithms.contains(tokenAlgorithm)) {
            throw new TokenValidationException(String.format("Signature algorithm of \"%s\" is not supported. Expected the ID token to be signed with any of %s.", tokenAlgorithm, supportedAlgorithms));
        }
    }

    abstract protected void checkSignature(@NonNull String[] tokenParts) throws TokenValidationException;


    /**
     * Creates a new SignatureVerifier for Asymmetric algorithm ("RS256"). Signature check will actually happen.
     *
     * @param keyId     the id of the key used to sign this token. Obtained from the token's header
     * @param apiClient the Authentication API client instance. Used to fetch the JWKs
     * @param callback  where to receive the results
     */
    static void forAsymmetricAlgorithm(@Nullable final String keyId, @NonNull AuthenticationAPIClient apiClient, @NonNull final BaseCallback<SignatureVerifier, TokenValidationException> callback) {
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
    }

    /**
     * Creates a new SignatureVerifier for when the algorithm is unknown or not set explicitly by the user. Only algorithm name is checked.
     *
     * @param callback where to receive the results
     */
    static void forUnknownAlgorithm(@NonNull final BaseCallback<SignatureVerifier, TokenValidationException> callback) {
        callback.onSuccess(new AlgorithmNameVerifier());
    }

}
