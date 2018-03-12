package com.auth0.android.authentication.storage;

import android.support.annotation.StringDef;

import com.auth0.android.Auth0Exception;

import java.lang.annotation.Retention;

import static java.lang.annotation.RetentionPolicy.SOURCE;

/**
 * Represents an error raised by the {@link CredentialsManager}.
 */
@SuppressWarnings("WeakerAccess")
public class CredentialsManagerException extends Auth0Exception {

    @Retention(SOURCE)
    @StringDef({
            NO_CREDENTIALS_SET,
            NO_AVAILABLE_REFRESH_TOKEN,
            INVALID_CREDENTIALS,
            RENEW_CREDENTIALS_ERROR,
            AUTHENTICATION_CHALLENGE_FAILED,
            ENCRYPTION_ERROR,
            DECRYPTION_ERROR
    })
    public @interface CredentialsManagerErrorMessages {}

    public static final String NO_CREDENTIALS_SET = "No Credentials were previously set.";
    public static final String NO_AVAILABLE_REFRESH_TOKEN = "Credentials have expired and no Refresh Token was available to renew them.";
    public static final String INVALID_CREDENTIALS = "Credentials must have a valid date of expiration and a valid access_token or id_token value.";
    public static final String RENEW_CREDENTIALS_ERROR = "An error occurred while trying to use the Refresh Token to renew the Credentials.";
    public static final String AUTHENTICATION_CHALLENGE_FAILED = "The user didn't pass the authentication challenge.";
    public static final String ENCRYPTION_ERROR = "An error occurred while encrypting the credentials.";
    public static final String DECRYPTION_ERROR = "An error occurred while decrypting the existing credentials.";

    public CredentialsManagerException(@CredentialsManagerErrorMessages String error) {
        super(error);
    }

    public CredentialsManagerException(@CredentialsManagerErrorMessages String error, Throwable cause) {
        super(error, cause);
    }

}
