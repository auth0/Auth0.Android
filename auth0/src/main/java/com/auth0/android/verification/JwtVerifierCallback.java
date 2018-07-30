package com.auth0.android.verification;

import com.auth0.android.jwt.JWT;

public interface JwtVerifierCallback {
    void onFailure(TokenVerificationException exception);

    void onSuccess(JWT jwt);
}
