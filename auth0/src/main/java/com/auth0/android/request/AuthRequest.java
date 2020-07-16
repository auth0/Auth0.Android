package com.auth0.android.request;

public interface AuthRequest extends AuthenticationRequest {

    /**
     * Add a header to the request, e.g. "Authorization"
     *
     * @param name  of the header
     * @param value of the header
     * @return itself
     */
    AuthRequest addHeader(String name, String value);

}
