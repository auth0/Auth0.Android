package com.auth0.android.auth0.lib.authentication;

import com.auth0.android.auth0.lib.Auth0Exception;
import com.auth0.android.auth0.lib.authentication.result.Credentials;
import com.auth0.android.auth0.lib.callback.BaseCallback;
import com.auth0.android.auth0.lib.request.ParameterizableRequest;
import com.auth0.android.auth0.lib.request.Request;

/**
 * Auth Request to obtain tokens using OAuth2 {@literal /oauth/token} method
 */
@SuppressWarnings("WeakerAccess")
public class TokenRequest implements Request<Credentials, AuthenticationException> {

    private static final String OAUTH_CODE_VERIFIER_KEY = "code_verifier";

    private final ParameterizableRequest<Credentials, AuthenticationException> request;

    TokenRequest(ParameterizableRequest<Credentials, AuthenticationException> request) {
        this.request = request;
    }

    /**
     * Adds the code verifier to the request (Public Clients)
     *
     * @param codeVerifier the code verifier used to generate the challenge sent to /authorize.
     * @return itself
     */
    @SuppressWarnings("WeakerAccess")
    public TokenRequest setCodeVerifier(String codeVerifier) {
        this.request.addParameter(OAUTH_CODE_VERIFIER_KEY, codeVerifier);
        return this;
    }

    @Override
    public void start(BaseCallback<Credentials, AuthenticationException> callback) {
        request.start(callback);
    }

    @Override
    public Credentials execute() throws Auth0Exception {
        return request.execute();
    }
}
