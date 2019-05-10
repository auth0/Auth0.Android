package com.auth0.android.authentication.storage;

import static android.text.TextUtils.isEmpty;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.ParameterizableRequest;
import com.auth0.android.result.Credentials;
import java.util.Date;

/**
 * Class that handles credentials and allows to save and retrieve them.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class CredentialsManager {
    private static final String KEY_ACCESS_TOKEN = "com.auth0.access_token";
    private static final String KEY_REFRESH_TOKEN = "com.auth0.refresh_token";
    private static final String KEY_ID_TOKEN = "com.auth0.id_token";
    private static final String KEY_TOKEN_TYPE = "com.auth0.token_type";
    private static final String KEY_EXPIRES_AT = "com.auth0.expires_at";
    private static final String KEY_SCOPE = "com.auth0.scope";

    private final AuthenticationAPIClient authClient;
    private final Storage storage;

    /**
     * Creates a new instance of the manager that will store the credentials in the given Storage.
     *
     * @param authenticationClient the Auth0 Authentication client to refresh credentials with.
     * @param storage              the storage to use for the credentials.
     */
    public CredentialsManager(@NonNull AuthenticationAPIClient authenticationClient, @NonNull Storage storage) {
        this.authClient = authenticationClient;
        this.storage = storage;
    }

    /**
     * Stores the given credentials in the storage. Must have an access_token or id_token and a expires_in value.
     *
     * @param credentials the credentials to save in the storage.
     */
    public void saveCredentials(@NonNull Credentials credentials) {
        if ((isEmpty(credentials.getAccessToken()) && isEmpty(credentials.getIdToken())) || credentials.getExpiresAt() == null) {
            throw new CredentialsManagerException("Credentials must have a valid date of expiration and a valid access_token or id_token value.");
        }
        storage.store(KEY_ACCESS_TOKEN, credentials.getAccessToken());
        storage.store(KEY_REFRESH_TOKEN, credentials.getRefreshToken());
        storage.store(KEY_ID_TOKEN, credentials.getIdToken());
        storage.store(KEY_TOKEN_TYPE, credentials.getType());
        storage.store(KEY_EXPIRES_AT, credentials.getExpiresAt().getTime());
        storage.store(KEY_SCOPE, credentials.getScope());
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with {@link CredentialsManagerException} if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param callback the callback that will receive a valid {@link Credentials} or the {@link CredentialsManagerException}.
     */
    public void getCredentials(@NonNull final BaseCallback<Credentials, CredentialsManagerException> callback) {
        getCredentials(null, callback);
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with {@link CredentialsManagerException} if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param callback the callback that will receive a valid {@link Credentials} or the {@link CredentialsManagerException}.
     */
    public void getCredentials(@Nullable final String scope,
                               @NonNull final BaseCallback<Credentials, CredentialsManagerException> callback) {
        String accessToken = storage.retrieveString(KEY_ACCESS_TOKEN);
        final String refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN);
        String idToken = storage.retrieveString(KEY_ID_TOKEN);
        String tokenType = storage.retrieveString(KEY_TOKEN_TYPE);
        Long expiresAt = storage.retrieveLong(KEY_EXPIRES_AT);
        String storedScope = storage.retrieveString(KEY_SCOPE);

        if (isEmpty(accessToken) && isEmpty(idToken) || expiresAt == null) {
            callback.onFailure(new CredentialsManagerException("No Credentials were previously set."));
            return;
        }
        if (expiresAt > getCurrentTimeInMillis()) {
            callback.onSuccess(recreateCredentials(idToken, accessToken, tokenType, refreshToken, new Date(expiresAt), storedScope));
            return;
        }
        if (refreshToken == null) {
            callback.onFailure(new CredentialsManagerException("Credentials have expired and no Refresh Token was available to renew them."));
            return;
        }

        ParameterizableRequest<Credentials, AuthenticationException> renewRequest = authClient.renewAuth(refreshToken);
        if (scope != null) {
            renewRequest = renewRequest.addParameter("scope", scope);
        }
        renewRequest.start(new AuthenticationCallback<Credentials>() {
            @Override
            public void onSuccess(Credentials fresh) {
                //RefreshTokens don't expire. It should remain the same
                Credentials credentials = new Credentials(fresh.getIdToken(), fresh.getAccessToken(), fresh.getType(), refreshToken, fresh.getExpiresAt(), fresh.getScope());
                saveCredentials(credentials);
                callback.onSuccess(credentials);
            }

            @Override
            public void onFailure(AuthenticationException error) {
                callback.onFailure(new CredentialsManagerException("An error occurred while trying to use the Refresh Token to renew the Credentials.", error));
            }
        });
    }

    /**
     * Checks if a non-expired pair of credentials can be obtained from this manager.
     *
     * @return whether there are valid credentials stored on this manager.
     */
    public boolean hasValidCredentials() {
        String accessToken = storage.retrieveString(KEY_ACCESS_TOKEN);
        String refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN);
        String idToken = storage.retrieveString(KEY_ID_TOKEN);
        Long expiresAt = storage.retrieveLong(KEY_EXPIRES_AT);

        return !(isEmpty(accessToken) && isEmpty(idToken) ||
            expiresAt == null ||
            expiresAt <= getCurrentTimeInMillis() && refreshToken == null);
    }

    /**
     * Removes the credentials from the storage if present.
     */
    public void clearCredentials() {
        storage.remove(KEY_ACCESS_TOKEN);
        storage.remove(KEY_REFRESH_TOKEN);
        storage.remove(KEY_ID_TOKEN);
        storage.remove(KEY_TOKEN_TYPE);
        storage.remove(KEY_EXPIRES_AT);
        storage.remove(KEY_SCOPE);
    }

    @VisibleForTesting
    Credentials recreateCredentials(String idToken, String accessToken, String tokenType, String refreshToken, Date expiresAt, String scope) {
        return new Credentials(idToken, accessToken, tokenType, refreshToken, expiresAt, scope);
    }

    @VisibleForTesting
    long getCurrentTimeInMillis() {
        return System.currentTimeMillis();
    }

}
