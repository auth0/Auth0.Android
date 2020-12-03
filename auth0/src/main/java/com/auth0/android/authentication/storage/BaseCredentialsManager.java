package com.auth0.android.authentication.storage;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.JWT;
import com.auth0.android.result.Credentials;
import com.auth0.android.util.Clock;

import java.util.Arrays;
import java.util.Date;

/**
 * Base class meant to abstract common logic across Credentials Manager implementations.
 * The scope of this class is package-private, as it's not meant to be exposed
 */
abstract class BaseCredentialsManager {

    protected final AuthenticationAPIClient authenticationClient;
    protected final Storage storage;
    protected final JWTDecoder jwtDecoder;
    protected Clock clock;

    BaseCredentialsManager(@NonNull AuthenticationAPIClient authenticationClient, @NonNull Storage storage, @NonNull JWTDecoder jwtDecoder) {
        this.authenticationClient = authenticationClient;
        this.storage = storage;
        this.jwtDecoder = jwtDecoder;
        this.clock = new ClockImpl();
    }

    public abstract void saveCredentials(@NonNull Credentials credentials) throws CredentialsManagerException;

    public abstract void getCredentials(@NonNull BaseCallback<Credentials, CredentialsManagerException> callback);

    public abstract void getCredentials(@Nullable String scope, int minTtl, @NonNull BaseCallback<Credentials, CredentialsManagerException> callback);

    public abstract void clearCredentials();

    public abstract boolean hasValidCredentials();

    public abstract boolean hasValidCredentials(long minTtl);

    /**
     * Updates the clock instance used for expiration verification purposes.
     * The use of this method can help on situations where the clock comes from an external synced source.
     * The default implementation uses the time returned by {@link System#currentTimeMillis()}.
     *
     * @param clock the new clock instance to use.
     */
    public void setClock(@NonNull Clock clock) {
        this.clock = clock;
    }

    @VisibleForTesting
    long getCurrentTimeInMillis() {
        return clock.getCurrentTimeMillis();
    }

    /**
     * Checks if the stored scope is the same as the requested one.
     *
     * @param storedScope   the stored scope, separated by space characters.
     * @param requiredScope the required scope, separated by space characters.
     * @return whether the scope are different or not
     */
    protected boolean hasScopeChanged(@NonNull String storedScope, @Nullable String requiredScope) {
        if (requiredScope == null) {
            return false;
        }
        String[] stored = storedScope.split(" ");
        Arrays.sort(stored);
        String[] required = requiredScope.split(" ");
        Arrays.sort(required);
        return !Arrays.equals(stored, required);
    }

    /**
     * Checks if given the required minimum time to live, the expiration time can satisfy that value or not.
     *
     * @param expiresAt the expiration time, in milliseconds.
     * @param minTtl    the time to live required, in seconds.
     * @return whether the value will become expired within the given min TTL or not.
     */
    protected boolean willExpire(long expiresAt, long minTtl) {
        if (expiresAt <= 0) {
            // Avoids logging out users when this value was not saved (migration scenario)
            return false;
        }
        long nextClock = getCurrentTimeInMillis() + minTtl * 1000;
        return expiresAt <= nextClock;
    }

    /**
     * Checks whether the given expiration time has been reached or not.
     *
     * @param expiresAt the expiration time, in milliseconds.
     * @return whether the given expiration time has been reached or not.
     */
    protected boolean hasExpired(long expiresAt) {
        return expiresAt <= getCurrentTimeInMillis();
    }

    /**
     * Takes a credentials object and returns the lowest expiration time, considering
     * both the access token and the ID token expiration time.
     *
     * @param credentials the credentials object to check.
     * @return the lowest expiration time between the access token and the ID token.
     */
    protected long calculateCacheExpiresAt(@NonNull Credentials credentials) {
        long expiresAt = credentials.getExpiresAt().getTime();

        if (credentials.getIdToken() != null) {
            JWT idToken = jwtDecoder.decode(credentials.getIdToken());
            Date idTokenExpiresAtDate = idToken.getExpiresAt();

            if (idTokenExpiresAtDate != null) {
                expiresAt = Math.min(idTokenExpiresAtDate.getTime(), expiresAt);
            }
        }
        return expiresAt;
    }
}
