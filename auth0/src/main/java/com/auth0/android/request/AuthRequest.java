package com.auth0.android.request;

import android.support.annotation.NonNull;

public interface AuthRequest extends AuthenticationRequest {

    /**
     * Add a header to the request, e.g. "Authorization"
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     */
    @NonNull
    AuthRequest addHeader(@NonNull String name, @NonNull String value);

}
