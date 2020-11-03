package com.auth0.android.authentication.storage;

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
import java.util.Locale;

import static android.text.TextUtils.isEmpty;

/**
 * Class that handles credentials and allows to save and retrieve them.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class CredentialsManager extends BaseCredentialsManager {
    private static final String KEY_ACCESS_TOKEN = "com.auth0.access_token";
    private static final String KEY_REFRESH_TOKEN = "com.auth0.refresh_token";
    private static final String KEY_ID_TOKEN = "com.auth0.id_token";
    private static final String KEY_TOKEN_TYPE = "com.auth0.token_type";
    private static final String KEY_EXPIRES_AT = "com.auth0.expires_at";
    private static final String KEY_SCOPE = "com.auth0.scope";
    private static final String KEY_CACHE_EXPIRES_AT = "com.auth0.cache_expires_at";

    @VisibleForTesting
    CredentialsManager(@NonNull AuthenticationAPIClient authenticationClient, @NonNull Storage storage, @NonNull JWTDecoder jwtDecoder) {
        super(authenticationClient, storage, jwtDecoder);
    }

    /**
     * Creates a new instance of the manager that will store the credentials in the given Storage.
     *
     * @param authenticationClient the Auth0 Authentication client to refresh credentials with.
     * @param storage              the storage to use for the credentials.
     */
    public CredentialsManager(@NonNull AuthenticationAPIClient authenticationClient, @NonNull Storage storage) {
        this(authenticationClient, storage, new JWTDecoder());
    }

    /**
     * Stores the given credentials in the storage. Must have an access_token or id_token and a expires_in value.
     *
     * @param credentials the credentials to save in the storage.
     */
    @Override
    public void saveCredentials(@NonNull Credentials credentials) {
        if ((isEmpty(credentials.getAccessToken()) && isEmpty(credentials.getIdToken())) || credentials.getExpiresAt() == null) {
            throw new CredentialsManagerException("Credentials must have a valid date of expiration and a valid access_token or id_token value.");
        }

        long cacheExpiresAt = calculateCacheExpiresAt(credentials);

        storage.store(KEY_ACCESS_TOKEN, credentials.getAccessToken());
        storage.store(KEY_REFRESH_TOKEN, credentials.getRefreshToken());
        storage.store(KEY_ID_TOKEN, credentials.getIdToken());
        storage.store(KEY_TOKEN_TYPE, credentials.getType());
        storage.store(KEY_EXPIRES_AT, credentials.getExpiresAt().getTime());
        storage.store(KEY_SCOPE, credentials.getScope());
        storage.store(KEY_CACHE_EXPIRES_AT, cacheExpiresAt);
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with {@link CredentialsManagerException} if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param callback the callback that will receive a valid {@link Credentials} or the {@link CredentialsManagerException}.
     */
    @Override
    public void getCredentials(@NonNull BaseCallback<Credentials, CredentialsManagerException> callback) {
        getCredentials(null, 0, callback);
    }

    /**
     * Retrieves the credentials from the storage and refresh them if they have already expired.
     * It will fail with {@link CredentialsManagerException} if the saved access_token or id_token is null,
     * or if the tokens have already expired and the refresh_token is null.
     *
     * @param scope    the scope to request for the access token. If null is passed, the previous scope will be kept.
     * @param minTtl   the minimum time in seconds that the access token should last before expiration.
     * @param callback the callback that will receive a valid {@link Credentials} or the {@link CredentialsManagerException}.
     */
    @Override
    public void getCredentials(@Nullable String scope, final int minTtl, @NonNull final BaseCallback<Credentials, CredentialsManagerException> callback) {
        String accessToken = storage.retrieveString(KEY_ACCESS_TOKEN);
        final String refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN);
        String idToken = storage.retrieveString(KEY_ID_TOKEN);
        String tokenType = storage.retrieveString(KEY_TOKEN_TYPE);
        Long expiresAt = storage.retrieveLong(KEY_EXPIRES_AT);
        String storedScope = storage.retrieveString(KEY_SCOPE);
        Long cacheExpiresAt = storage.retrieveLong(KEY_CACHE_EXPIRES_AT);
        if (cacheExpiresAt == null) {
            cacheExpiresAt = expiresAt;
        }

        boolean hasEmptyCredentials = isEmpty(accessToken) && isEmpty(idToken) || expiresAt == null;
        if (hasEmptyCredentials) {
            callback.onFailure(new CredentialsManagerException("No Credentials were previously set."));
            return;
        }

        boolean hasEitherExpired = hasExpired(cacheExpiresAt);
        boolean willAccessTokenExpire = willExpire(expiresAt, minTtl);
        boolean scopeChanged = hasScopeChanged(storedScope, scope);

        if (!hasEitherExpired && !willAccessTokenExpire && !scopeChanged) {
            callback.onSuccess(recreateCredentials(idToken, accessToken, tokenType, refreshToken, new Date(expiresAt), storedScope));
            return;
        }
        if (refreshToken == null) {
            callback.onFailure(new CredentialsManagerException("Credentials need to be renewed but no Refresh Token is available to renew them."));
            return;
        }

        final ParameterizableRequest<Credentials, AuthenticationException> request = authenticationClient.renewAuth(refreshToken);
        if (scope != null) {
            request.addParameter("scope", scope);
        }
        request.start(new AuthenticationCallback<Credentials>() {
            @Override
            public void onSuccess(@Nullable Credentials fresh) {
                long expiresAt = fresh.getExpiresAt().getTime();
                boolean willAccessTokenExpire = willExpire(expiresAt, minTtl);
                if (willAccessTokenExpire) {
                    long tokenLifetime = (expiresAt - getCurrentTimeInMillis() - minTtl * 1000) / -1000;
                    CredentialsManagerException wrongTtlException = new CredentialsManagerException(String.format(Locale.getDefault(), "The lifetime of the renewed Access Token (%d) is less than the minTTL requested (%d). Increase the 'Token Expiration' setting of your Auth0 API in the dashboard, or request a lower minTTL.", tokenLifetime, minTtl));
                    callback.onFailure(wrongTtlException);
                    return;
                }

                //non-empty refresh token for refresh token rotation scenarios
                String updatedRefreshToken = isEmpty(fresh.getRefreshToken()) ? refreshToken : fresh.getRefreshToken();
                Credentials credentials = new Credentials(fresh.getIdToken(), fresh.getAccessToken(), fresh.getType(), updatedRefreshToken, fresh.getExpiresAt(), fresh.getScope());
                saveCredentials(credentials);
                callback.onSuccess(credentials);
            }

            @Override
            public void onFailure(@NonNull AuthenticationException error) {
                callback.onFailure(new CredentialsManagerException("An error occurred while trying to use the Refresh Token to renew the Credentials.", error));
            }
        });

    }

    /**
     * Checks if a non-expired pair of credentials can be obtained from this manager.
     *
     * @return whether there are valid credentials stored on this manager.
     */
    @Override
    public boolean hasValidCredentials() {
        return hasValidCredentials(0);
    }

    /**
     * Checks if a non-expired pair of credentials can be obtained from this manager.
     *
     * @param minTtl the minimum time in seconds that the access token should last before expiration.
     * @return whether there are valid credentials stored on this manager.
     */
    @Override
    public boolean hasValidCredentials(long minTtl) {
        String accessToken = storage.retrieveString(KEY_ACCESS_TOKEN);
        String refreshToken = storage.retrieveString(KEY_REFRESH_TOKEN);
        String idToken = storage.retrieveString(KEY_ID_TOKEN);
        Long expiresAt = storage.retrieveLong(KEY_EXPIRES_AT);
        Long cacheExpiresAt = storage.retrieveLong(KEY_CACHE_EXPIRES_AT);
        if (cacheExpiresAt == null) {
            cacheExpiresAt = expiresAt;
        }

        boolean emptyCredentials = isEmpty(accessToken) && isEmpty(idToken) || cacheExpiresAt == null || expiresAt == null;
        return !(emptyCredentials || (hasExpired(cacheExpiresAt) || willExpire(expiresAt, minTtl)) && refreshToken == null);
    }

    /**
     * Removes the credentials from the storage if present.
     */
    @Override
    public void clearCredentials() {
        storage.remove(KEY_ACCESS_TOKEN);
        storage.remove(KEY_REFRESH_TOKEN);
        storage.remove(KEY_ID_TOKEN);
        storage.remove(KEY_TOKEN_TYPE);
        storage.remove(KEY_EXPIRES_AT);
        storage.remove(KEY_SCOPE);
        storage.remove(KEY_CACHE_EXPIRES_AT);
    }

    @VisibleForTesting
    Credentials recreateCredentials(String idToken, String accessToken, String tokenType, String refreshToken, Date expiresAt, String scope) {
        return new Credentials(idToken, accessToken, tokenType, refreshToken, expiresAt, scope);
    }

}
