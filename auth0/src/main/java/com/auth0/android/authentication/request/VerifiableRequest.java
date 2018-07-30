package com.auth0.android.authentication.request;

import android.support.annotation.NonNull;
import android.text.TextUtils;

import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.AuthenticationCallback;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.request.Request;
import com.auth0.android.result.Credentials;
import com.auth0.android.verification.JwtVerifier;
import com.auth0.android.verification.TokenVerificationException;

public class VerifiableRequest implements Request<Credentials, AuthenticationException> {

    private final JwtVerifier verifier;
    private final Request<Credentials, AuthenticationException> baseRequest;

    public VerifiableRequest(@NonNull JwtVerifier verifier, @NonNull Request<Credentials, AuthenticationException> credentialsRequest) {
        this.verifier = verifier;
        this.baseRequest = credentialsRequest;
    }

    @Override
    public void start(final BaseCallback<Credentials, AuthenticationException> callback) {
        baseRequest.start(new AuthenticationCallback<Credentials>() {
            @Override
            public void onSuccess(final Credentials credentials) {
                String idToken = credentials.getIdToken();
                if (TextUtils.isEmpty(idToken)) {
                    callback.onSuccess(credentials);
                    return;
                }
                verifier.verify(idToken, new BaseCallback<Void, TokenVerificationException>() {
                    @Override
                    public void onSuccess(Void payload) {
                        callback.onSuccess(credentials);
                    }

                    @Override
                    public void onFailure(TokenVerificationException error) {
                        callback.onFailure(new AuthenticationException("The Id Token could not be verified", error));
                    }
                });
            }

            @Override
            public void onFailure(AuthenticationException error) {
                callback.onFailure(error);
            }
        });
    }

    @Override
    public Credentials execute() throws Auth0Exception {
        //FIXME: This won't work. Let's make the Verifier SYNC and wrap the call for the async above
        final Credentials credentials = baseRequest.execute();
        String idToken = credentials.getIdToken();
        if (!TextUtils.isEmpty(idToken)) {
            verifier.verify(idToken, new BaseCallback<Void, TokenVerificationException>() {
                @Override
                public void onFailure(TokenVerificationException exception) {
                    throw new Auth0Exception("The Id Token verification failed", exception);
                }

                @Override
                public void onSuccess(Void payload) {
                }
            });
        }
        return credentials;
    }

}
