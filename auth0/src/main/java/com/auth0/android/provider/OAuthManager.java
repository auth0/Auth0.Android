package com.auth0.android.provider;

import android.app.Activity;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;
import com.auth0.android.authentication.AuthenticationAPIClient;
import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.callback.BaseCallback;
import com.auth0.android.jwt.DecodeException;
import com.auth0.android.jwt.JWT;
import com.auth0.android.result.Credentials;

import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("WeakerAccess")
class OAuthManager extends ResumableManager {

    private static final String TAG = OAuthManager.class.getSimpleName();

    static final String KEY_RESPONSE_TYPE = "response_type";
    static final String KEY_STATE = "state";
    static final String KEY_NONCE = "nonce";
    static final String KEY_MAX_AGE = "max_age";
    static final String KEY_CONNECTION = "connection";
    static final String RESPONSE_TYPE_ID_TOKEN = "id_token";
    static final String RESPONSE_TYPE_CODE = "code";

    private static final String ERROR_VALUE_INVALID_CONFIGURATION = "a0.invalid_configuration";
    private static final String ERROR_VALUE_AUTHENTICATION_CANCELED = "a0.authentication_canceled";
    private static final String ERROR_VALUE_ACCESS_DENIED = "access_denied";
    private static final String ERROR_VALUE_UNAUTHORIZED = "unauthorized";
    private static final String ERROR_VALUE_LOGIN_REQUIRED = "login_required";
    private static final String ERROR_VALUE_ID_TOKEN_VALIDATION_FAILED = "Could not verify the ID token";
    private static final String METHOD_SHA_256 = "S256";
    private static final String KEY_CODE_CHALLENGE = "code_challenge";
    private static final String KEY_CODE_CHALLENGE_METHOD = "code_challenge_method";
    private static final String KEY_CLIENT_ID = "client_id";
    private static final String KEY_REDIRECT_URI = "redirect_uri";
    private static final String KEY_TELEMETRY = "auth0Client";
    private static final String KEY_ERROR = "error";
    private static final String KEY_ERROR_DESCRIPTION = "error_description";
    private static final String KEY_ID_TOKEN = "id_token";
    private static final String KEY_ACCESS_TOKEN = "access_token";
    private static final String KEY_TOKEN_TYPE = "token_type";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_CODE = "code";
    private static final String KEY_SCOPE = "scope";

    private final Auth0 account;
    private final AuthCallback callback;
    private final Map<String, String> parameters;
    private final AuthenticationAPIClient apiClient;

    private boolean useFullScreen;
    private boolean useBrowser = true;
    private int requestCode;
    private PKCE pkce;
    private Long currentTimeInMillis;
    private CustomTabsOptions ctOptions;
    private Integer idTokenVerificationLeeway;
    private String idTokenVerificationIssuer;
    private Map<String, String> headers;

    OAuthManager(@NonNull Auth0 account, @NonNull AuthCallback callback, @NonNull Map<String, String> parameters) {
        this.account = account;
        this.callback = callback;
        this.parameters = new HashMap<>(parameters);
        this.apiClient = new AuthenticationAPIClient(account);
        this.headers = new HashMap<>();
    }

    void useFullScreen(boolean useFullScreen) {
        this.useFullScreen = useFullScreen;
    }

    void useBrowser(boolean useBrowser) {
        this.useBrowser = useBrowser;
    }

    public void setCustomTabsOptions(@Nullable CustomTabsOptions options) {
        this.ctOptions = options;
    }

    @VisibleForTesting
    void setPKCE(PKCE pkce) {
        this.pkce = pkce;
    }

    void setIdTokenVerificationLeeway(Integer leeway) {
        this.idTokenVerificationLeeway = leeway;
    }

    void setIdTokenVerificationIssuer(String issuer) {
        this.idTokenVerificationIssuer = TextUtils.isEmpty(issuer) ? apiClient.getBaseURL() : issuer;
    }

    void startAuthentication(Activity activity, String redirectUri, int requestCode) {
        addPKCEParameters(parameters, redirectUri);
        addPKCEHeaders(headers);
        addClientParameters(parameters, redirectUri);
        addValidationParameters(parameters);
        Uri uri = buildAuthorizeUri();
        this.requestCode = requestCode;

        if (useBrowser) {
            AuthenticationActivity.authenticateUsingBrowser(activity, uri, ctOptions);
        } else {
            AuthenticationActivity.authenticateUsingWebView(activity, uri, requestCode, parameters.get(KEY_CONNECTION), useFullScreen);
        }
    }

    void setHeaders(@NonNull Map<String, String> headers) {
        this.headers.putAll(headers);
    }

    @Override
    boolean resume(AuthorizeResult result) {
        if (!result.isValid(requestCode)) {
            Log.w(TAG, "The Authorize Result is invalid.");
            return false;
        }

        if (result.isCanceled()) {
            //User cancelled the authentication
            AuthenticationException exception = new AuthenticationException(ERROR_VALUE_AUTHENTICATION_CANCELED, "The user closed the browser app and the authentication was canceled.");
            callback.onFailure(exception);
            return true;
        }

        final Map<String, String> values = CallbackHelper.getValuesFromUri(result.getIntentData());
        if (values.isEmpty()) {
            Log.w(TAG, "The response didn't contain any of these values: code, state, id_token, access_token, token_type, refresh_token");
            return false;
        }
        logDebug("The parsed CallbackURI contains the following values: " + values);

        try {
            assertNoError(values.get(KEY_ERROR), values.get(KEY_ERROR_DESCRIPTION));
            assertValidState(parameters.get(KEY_STATE), values.get(KEY_STATE));
        } catch (AuthenticationException e) {
            callback.onFailure(e);
            return true;
        }

        final Date expiresAt = !values.containsKey(KEY_EXPIRES_IN) ? null : new Date(getCurrentTimeInMillis() + Long.parseLong(values.get(KEY_EXPIRES_IN)) * 1000);
        boolean frontChannelIdTokenExpected = parameters.containsKey(KEY_RESPONSE_TYPE) && parameters.get(KEY_RESPONSE_TYPE).contains(RESPONSE_TYPE_ID_TOKEN);
        final Credentials frontChannelCredentials = new Credentials(frontChannelIdTokenExpected ? values.get(KEY_ID_TOKEN) : null, values.get(KEY_ACCESS_TOKEN), values.get(KEY_TOKEN_TYPE), null, expiresAt, values.get(KEY_SCOPE));

        if (frontChannelIdTokenExpected) {
            //Must be response_type=id_token (or additional values)
            assertValidIdToken(frontChannelCredentials.getIdToken(), new VoidCallback() {
                @Override
                public void onSuccess(@Nullable Void ignored) {
                    if (!shouldUsePKCE()) {
                        //response_type=id_token or response_type=id_token token
                        callback.onSuccess(frontChannelCredentials);
                        return;
                    }
                    //response_type=id_token code
                    pkce.getToken(values.get(KEY_CODE), new SimpleAuthCallback(callback) {

                        @Override
                        public void onSuccess(@NonNull Credentials credentials) {
                            Credentials finalCredentials = mergeCredentials(frontChannelCredentials, credentials);
                            callback.onSuccess(finalCredentials);
                        }
                    });
                }

                @Override
                public void onFailure(@NonNull Auth0Exception error) {
                    AuthenticationException wrappedError = new AuthenticationException(ERROR_VALUE_ID_TOKEN_VALIDATION_FAILED, error);
                    callback.onFailure(wrappedError);
                }
            });
            return true;
        }

        if (!shouldUsePKCE()) {
            //Must be response_type=token
            callback.onSuccess(frontChannelCredentials);
            return true;
        }

        //Either response_type=code or response_type=token code
        pkce.getToken(values.get(KEY_CODE), new SimpleAuthCallback(callback) {

            @Override
            public void onSuccess(@NonNull final Credentials credentials) {
                assertValidIdToken(credentials.getIdToken(), new VoidCallback() {
                    @Override
                    public void onSuccess(@Nullable Void ignored) {
                        Credentials finalCredentials = mergeCredentials(frontChannelCredentials, credentials);
                        callback.onSuccess(finalCredentials);
                    }

                    @Override
                    public void onFailure(@Nullable Auth0Exception error) {
                        AuthenticationException wrappedError = new AuthenticationException(ERROR_VALUE_ID_TOKEN_VALIDATION_FAILED, error);
                        callback.onFailure(wrappedError);
                    }
                });
            }
        });
        return true;
    }

    private void assertValidIdToken(String idToken, final VoidCallback validationCallback) {
        if (TextUtils.isEmpty(idToken)) {
            validationCallback.onFailure(new TokenValidationException("ID token is required but missing"));
            return;
        }
        final JWT decodedIdToken;
        try {
            decodedIdToken = new JWT(idToken);
        } catch (DecodeException ignored) {
            validationCallback.onFailure(new TokenValidationException("ID token could not be decoded"));
            return;
        }

        BaseCallback<SignatureVerifier, TokenValidationException> signatureVerifierCallback = new BaseCallback<SignatureVerifier, TokenValidationException>() {

            @Override
            public void onFailure(@NonNull TokenValidationException error) {
                validationCallback.onFailure(error);
            }

            @Override
            public void onSuccess(@Nullable SignatureVerifier signatureVerifier) {
                //noinspection ConstantConditions
                IdTokenVerificationOptions options = new IdTokenVerificationOptions(idTokenVerificationIssuer, apiClient.getClientId(), signatureVerifier);
                String maxAge = parameters.get(KEY_MAX_AGE);
                if (!TextUtils.isEmpty(maxAge)) {
                    //noinspection ConstantConditions
                    options.setMaxAge(Integer.valueOf(maxAge));
                }
                options.setClockSkew(idTokenVerificationLeeway);
                options.setNonce(parameters.get(KEY_NONCE));
                options.setClock(new Date(getCurrentTimeInMillis()));
                try {
                    new IdTokenVerifier().verify(decodedIdToken, options);
                    logDebug("Authenticated using web flow");
                    validationCallback.onSuccess(null);
                } catch (TokenValidationException exc) {
                    validationCallback.onFailure(exc);
                }
            }
        };

        String tokenAlg = decodedIdToken.getHeader().get("alg");
        if (account.isOIDCConformant() || "RS256".equals(tokenAlg)) {
            String tokenKeyId = decodedIdToken.getHeader().get("kid");
            SignatureVerifier.forAsymmetricAlgorithm(tokenKeyId, apiClient, signatureVerifierCallback);
        } else {
            SignatureVerifier.forUnknownAlgorithm(signatureVerifierCallback);
        }
    }

    private long getCurrentTimeInMillis() {
        return currentTimeInMillis != null ? currentTimeInMillis : System.currentTimeMillis();
    }

    @VisibleForTesting
    void setCurrentTimeInMillis(long currentTimeInMillis) {
        this.currentTimeInMillis = currentTimeInMillis;
    }

    //Helper Methods

    private void assertNoError(String errorValue, String errorDescription) throws AuthenticationException {
        if (errorValue == null) {
            return;
        }
        Log.e(TAG, "Error, access denied. Check that the required Permissions are granted and that the Application has this Connection configured in Auth0 Dashboard.");
        if (ERROR_VALUE_ACCESS_DENIED.equalsIgnoreCase(errorValue)) {
            throw new AuthenticationException(ERROR_VALUE_ACCESS_DENIED, "Permissions were not granted. Try again.");
        } else if (ERROR_VALUE_UNAUTHORIZED.equalsIgnoreCase(errorValue)) {
            throw new AuthenticationException(ERROR_VALUE_UNAUTHORIZED, errorDescription);
        } else if (ERROR_VALUE_LOGIN_REQUIRED.equals(errorValue)) {
            //Whitelist to allow SSO errors go through
            throw new AuthenticationException(errorValue, errorDescription);
        } else {
            throw new AuthenticationException(ERROR_VALUE_INVALID_CONFIGURATION, "The application isn't configured properly for the social connection. Please check your Auth0's application configuration");
        }
    }

    @VisibleForTesting
    static void assertValidState(@NonNull String requestState, @Nullable String responseState) throws AuthenticationException {
        if (!requestState.equals(responseState)) {
            Log.e(TAG, String.format("Received state doesn't match. Received %s but expected %s", responseState, requestState));
            throw new AuthenticationException(ERROR_VALUE_ACCESS_DENIED, "The received state is invalid. Try again.");
        }
    }

    private Uri buildAuthorizeUri() {
        Uri authorizeUri = Uri.parse(account.getAuthorizeUrl());
        Uri.Builder builder = authorizeUri.buildUpon();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            builder.appendQueryParameter(entry.getKey(), entry.getValue());
        }
        Uri uri = builder.build();
        logDebug("Using the following Authorize URI: " + uri.toString());
        return uri;
    }

    private void addPKCEParameters(Map<String, String> parameters, String redirectUri) {
        if (!shouldUsePKCE()) {
            return;
        }
        try {
            createPKCE(redirectUri);
            String codeChallenge = pkce.getCodeChallenge();
            parameters.put(KEY_CODE_CHALLENGE, codeChallenge);
            parameters.put(KEY_CODE_CHALLENGE_METHOD, METHOD_SHA_256);
            Log.v(TAG, "Using PKCE authentication flow");
        } catch (IllegalStateException e) {
            Log.e(TAG, "Some algorithms aren't available on this device and PKCE can't be used. Defaulting to token response_type.", e);
        }
    }

    private void addPKCEHeaders(@NonNull Map<String, String> httpHeaders) {
        if (!shouldUsePKCE()) {
            return;
        }

        pkce.setHeaders(httpHeaders);
    }

    private void addValidationParameters(Map<String, String> parameters) {
        String state = getRandomString(parameters.get(KEY_STATE));
        parameters.put(KEY_STATE, state);

        boolean idTokenExpected = parameters.containsKey(KEY_RESPONSE_TYPE) && (parameters.get(KEY_RESPONSE_TYPE).contains(RESPONSE_TYPE_ID_TOKEN) || parameters.get(KEY_RESPONSE_TYPE).contains(RESPONSE_TYPE_CODE));
        if (idTokenExpected) {
            String nonce = getRandomString(parameters.get(KEY_NONCE));
            parameters.put(KEY_NONCE, nonce);
        }
    }

    private void addClientParameters(Map<String, String> parameters, String redirectUri) {
        if (account.getTelemetry() != null) {
            parameters.put(KEY_TELEMETRY, account.getTelemetry().getValue());
        }
        parameters.put(KEY_CLIENT_ID, account.getClientId());
        parameters.put(KEY_REDIRECT_URI, redirectUri);
    }

    private void createPKCE(String redirectUri) {
        if (pkce == null) {
            pkce = new PKCE(apiClient, redirectUri);
        }
    }

    private boolean shouldUsePKCE() {
        return parameters.containsKey(KEY_RESPONSE_TYPE) && parameters.get(KEY_RESPONSE_TYPE).contains(RESPONSE_TYPE_CODE) && PKCE.isAvailable();
    }

    @VisibleForTesting
    boolean useBrowser() {
        return useBrowser;
    }

    @VisibleForTesting
    boolean useFullScreen() {
        return useFullScreen;
    }

    @VisibleForTesting
    CustomTabsOptions customTabsOptions() {
        return ctOptions;
    }

    @VisibleForTesting
    static Credentials mergeCredentials(Credentials urlCredentials, Credentials codeCredentials) {
        final String idToken = TextUtils.isEmpty(urlCredentials.getIdToken()) ? codeCredentials.getIdToken() : urlCredentials.getIdToken();
        final String accessToken = TextUtils.isEmpty(codeCredentials.getAccessToken()) ? urlCredentials.getAccessToken() : codeCredentials.getAccessToken();
        final String type = TextUtils.isEmpty(codeCredentials.getType()) ? urlCredentials.getType() : codeCredentials.getType();
        final String refreshToken = codeCredentials.getRefreshToken();
        final Date expiresAt = codeCredentials.getExpiresAt() != null ? codeCredentials.getExpiresAt() : urlCredentials.getExpiresAt();
        final String scope = TextUtils.isEmpty(codeCredentials.getScope()) ? urlCredentials.getScope() : codeCredentials.getScope();

        return new Credentials(idToken, accessToken, type, refreshToken, expiresAt, scope);
    }

    @VisibleForTesting
    static String getRandomString(@Nullable String defaultValue) {
        return defaultValue != null ? defaultValue : secureRandomString();
    }

    private static String secureRandomString() {
        final SecureRandom sr = new SecureRandom();
        final byte[] randomBytes = new byte[32];
        sr.nextBytes(randomBytes);
        return Base64.encodeToString(randomBytes, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    private void logDebug(String message) {
        if (account.isLoggingEnabled()) {
            Log.d(TAG, message);
        }
    }
}
