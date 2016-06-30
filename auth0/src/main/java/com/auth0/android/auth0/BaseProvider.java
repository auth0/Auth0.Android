package com.auth0.android.auth0;

import android.support.annotation.NonNull;

public interface BaseProvider {

    /**
     * Stops the authentication process (even if it's in progress).
     */
    @SuppressWarnings("unused")
    void stop();

    /**
     * Removes any session information stored in the object.
     */
    @SuppressWarnings("unused")
    void clearSession();

    /**
     * Finishes the auth flow by parsing the AuthorizeResult. The authentication result
     * will be notified to the callback.
     *
     * @param result the result received in the activity.
     * @return if the result is valid or not. Please note, this only means that the result has a valid format.
     * The authentication result will be notified to the callback.
     */
    boolean authorize(@NonNull AuthorizeResult result);
}
