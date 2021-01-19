package com.auth0.android.provider;

import androidx.annotation.NonNull;

import com.auth0.android.request.internal.Jwt;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static android.text.TextUtils.isEmpty;

class IdTokenVerifier {
    private static final Integer DEFAULT_CLOCK_SKEW = 60; // 1 min = 60 sec

    /**
     * Verifies a provided ID Token follows the OIDC specification.
     * See https://openid.net/specs/openid-connect-core-1_0-final.html#IDTokenValidation
     *
     * @param token         the ID Token to verify.
     * @param verifyOptions the verification options, like audience, issuer, algorithm.
     * @throws TokenValidationException If the ID Token is null, its signing algorithm not supported, its signature invalid or one of its claim invalid.
     */
    void verify(@NonNull Jwt token, @NonNull IdTokenVerificationOptions verifyOptions) throws TokenValidationException {
        verifyOptions.getSignatureVerifier().verify(token);

        if (isEmpty(token.getIssuer())) {
            throw new TokenValidationException("Issuer (iss) claim must be a string present in the ID token");
        }
        //noinspection ConstantConditions
        if (!token.getIssuer().equals(verifyOptions.getIssuer())) {
            throw new TokenValidationException(String.format("Issuer (iss) claim mismatch in the ID token, expected \"%s\", found \"%s\"", verifyOptions.getIssuer(), token.getIssuer()));
        }

        if (isEmpty(token.getSubject())) {
            throw new TokenValidationException("Subject (sub) claim must be a string present in the ID token");
        }

        final List<String> audience = token.getAudience();
        if (audience == null || audience.isEmpty()) {
            throw new TokenValidationException("Audience (aud) claim must be a string or array of strings present in the ID token");
        }
        if (!audience.contains(verifyOptions.getAudience())) {
            throw new TokenValidationException(String.format("Audience (aud) claim mismatch in the ID token; expected \"%s\" but was not one of \"%s\"", verifyOptions.getAudience(), token.getAudience()));
        }

        final Calendar cal = Calendar.getInstance();
        final Date now = verifyOptions.getClock() != null ? verifyOptions.getClock() : cal.getTime();
        final int clockSkew = verifyOptions.getClockSkew() != null ? verifyOptions.getClockSkew() : DEFAULT_CLOCK_SKEW;

        if (token.getExpiresAt() == null) {
            throw new TokenValidationException("Expiration Time (exp) claim must be a number present in the ID token");
        }

        cal.setTime(token.getExpiresAt());
        cal.add(Calendar.SECOND, clockSkew);
        Date expDate = cal.getTime();

        if (now.after(expDate)) {
            throw new TokenValidationException(String.format("Expiration Time (exp) claim error in the ID token; current time (%d) is after expiration time (%d)", now.getTime() / 1000, expDate.getTime() / 1000));
        }

        if (token.getIssuedAt() == null) {
            throw new TokenValidationException("Issued At (iat) claim must be a number present in the ID token");
        }

        if (verifyOptions.getNonce() != null) {
            String nonceClaim = token.getNonce();
            if (isEmpty(nonceClaim)) {
                throw new TokenValidationException("Nonce (nonce) claim must be a string present in the ID token");
            }
            if (!verifyOptions.getNonce().equals(nonceClaim)) {
                throw new TokenValidationException(String.format("Nonce (nonce) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.getNonce(), nonceClaim));
            }
        }

        if (audience.size() > 1) {
            String azpClaim = token.getAuthorizedParty();
            if (isEmpty(azpClaim)) {
                throw new TokenValidationException("Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values");
            }
            if (!verifyOptions.getAudience().equals(azpClaim)) {
                throw new TokenValidationException(String.format("Authorized Party (azp) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.getAudience(), azpClaim));
            }
        }

        if (verifyOptions.getMaxAge() != null) {
            Date authTime = token.getAuthenticationTime();
            if (authTime == null) {
                throw new TokenValidationException("Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified");
            }

            cal.setTime(authTime);
            cal.add(Calendar.SECOND, verifyOptions.getMaxAge());
            cal.add(Calendar.SECOND, clockSkew);
            Date authTimeDate = cal.getTime();

            if (now.after(authTimeDate)) {
                throw new TokenValidationException(String.format("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (%d) is after last auth at (%d)", now.getTime() / 1000, authTimeDate.getTime() / 1000));
            }
        }
    }

}
