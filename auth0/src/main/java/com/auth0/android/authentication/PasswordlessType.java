package com.auth0.android.authentication;

import androidx.annotation.NonNull;

/**
 * Valid types of passwordless flows in Auth0
 */
public enum PasswordlessType {
    /**
     * Sends a link used to login
     */
    WEB_LINK,
    ANDROID_LINK,
    CODE;

    @NonNull
    public String getValue() {
        switch (this) {
            default:
            case CODE:
                return "code";
            case WEB_LINK:
                return "link";
            case ANDROID_LINK:
                return "link_android";
        }
    }
}
