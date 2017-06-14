package com.auth0.android.authentication.storage;

import android.support.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.result.Credentials;

import static android.text.TextUtils.isEmpty;

public class CredentialsManager {
    private static final String KEY_ACCESS_TOKEN = "com.auth0.access_token";
    private static final String KEY_REFRESH_TOKEN = "com.auth0.refresh_token";
    private static final String KEY_ID_TOKEN = "com.auth0.id_token";
    private static final String KEY_TOKEN_TYPE = "com.auth0.token_type";
    private static final String KEY_EXPIRES_IN = "com.auth0.expires_in";
    private static final String KEY_EXPIRATION_TIME = "com.auth0.expiration_time";

    private final AuthenticationAPIClient authClient;
    private final Storage storage;

    public CredentialsManager(@NonNull AuthenticationAPIClient authenticationClient, @NonNull Storage storage) {
        this.authClient = authenticationClient;
        this.storage = storage;
    }

    public void setCredentials(@NonNull Credentials credentials) {
        if ((credentials.getAccessToken() == null && credentials.getIdToken() == null) || credentials.getExpiresIn() == null) {
            throw new CredentialsManagerException("Credentials must have a valid expires_in value and a valid access_token or id_token value.");
        }
        storage.save(KEY_ACCESS_TOKEN, credentials.getAccessToken());
        storage.save(KEY_REFRESH_TOKEN, credentials.getRefreshToken());
        storage.save(KEY_ID_TOKEN, credentials.getIdToken());
        storage.save(KEY_TOKEN_TYPE, credentials.getType());

        long expiresIn = credentials.getExpiresIn() == null ? 0 : credentials.getExpiresIn();
        storage.save(KEY_EXPIRES_IN, Long.toString(expiresIn));
        long expirationTime = System.currentTimeMillis() + (expiresIn * 1000);
        storage.save(KEY_EXPIRATION_TIME, Long.toString(expirationTime));
    }

    public void getCredentials(@NonNull final BaseCallback<Credentials, CredentialsManagerException> callback) {
        String accessToken = storage.retrieve(KEY_ACCESS_TOKEN);
        String refreshToken = storage.retrieve(KEY_REFRESH_TOKEN);
        String idToken = storage.retrieve(KEY_ID_TOKEN);
        String tokenType = storage.retrieve(KEY_TOKEN_TYPE);
        String expiresInValue = storage.retrieve(KEY_EXPIRES_IN);
        String expirationTimeValue = storage.retrieve(KEY_EXPIRATION_TIME);
        Long expiresIn = Long.parseLong(expiresInValue);

        boolean invalidTokens = isEmpty(accessToken) && isEmpty(idToken);
        if (invalidTokens) {
            callback.onFailure(new CredentialsManagerException("No Credentials where previously set."));
            return;
        }
        long expirationTime = expirationTimeValue == null ? 0 : Long.parseLong(expirationTimeValue);
        if (expirationTime > System.currentTimeMillis()) {
            callback.onSuccess(new Credentials(idToken, accessToken, tokenType, refreshToken, expiresIn));
            return;
        }
        if (refreshToken == null) {
            callback.onFailure(new CredentialsManagerException("No Refresh Token available."));
            return;
        }

        authClient.renewAuth(refreshToken).start(new AuthenticationCallback<Credentials>() {
            @Override
            public void onSuccess(Credentials freshCredentials) {
                callback.onSuccess(freshCredentials);
            }

            @Override
            public void onFailure(AuthenticationException error) {
                callback.onFailure(new CredentialsManagerException("An error occurred while trying to use the refresh_token to renew the credentials.", error));
            }
        });
    }

}
