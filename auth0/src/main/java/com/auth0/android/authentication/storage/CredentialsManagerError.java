package com.auth0.android.authentication.storage;

/**
 * Represents the different error raised by the {@link CredentialsManager} and their message.
 */
public enum CredentialsManagerError {

    NO_CREDENTIALS_SET("No Credentials were previously set."),
    NO_AVAILABLE_REFRESH_TOKEN("Credentials have expired and no Refresh Token was available to renew them."),
    INVALID_CREDENTIALS("Credentials must have a valid date of expiration and a valid access_token or id_token value."),
    RENEW_CREDENTIALS_ERROR("An error occurred while trying to use the Refresh Token to renew the Credentials."),
    AUTHENTICATION_CHALLENGE_FAILED("The user didn't pass the authentication challenge."),
    ENCRYPTION_ERROR("An error occurred while encrypting the credentials."),
    DECRYPTION_ERROR("An error occurred while decrypting the existing credentials.");

    private String message;

    CredentialsManagerError(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
