package com.auth0.android.jwt;

import android.support.annotation.NonNull;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static android.text.TextUtils.isEmpty;

//TODO: Make pkg private
public class IdTokenVerifier {
    private static final Integer DEFAULT_CLOCK_SKEW = 60; //1 min = 60 sec

    private static final String NONCE_CLAIM = "nonce";
    private static final String AZP_CLAIM = "azp";
    private static final String AUTH_TIME_CLAIM = "auth_time";

    /**
     * Verifies a provided ID Token follows the OIDC specification.
     * See https://openid.net/specs/openid-connect-core-1_0-final.html#IDTokenValidation
     *
     * @param token         the ID Token to verify.
     * @param verifyOptions the verification options, like audience, issuer, algorithm.
     * @throws TokenValidationException If the ID Token is null, its signing algorithm not supported, its signature invalid or one of its claim invalid.
     */
    public void verify(@NonNull JWT token, @NonNull Options verifyOptions) throws TokenValidationException {
        verifyOptions.verifier.verifySignature(token);

        if (isEmpty(token.getIssuer())) {
            throw new TokenValidationException("Issuer (iss) claim must be a string present in the ID token");
        }
        //noinspection ConstantConditions
        if (!token.getIssuer().equals(verifyOptions.issuer)) {
            throw new TokenValidationException(String.format("Issuer (iss) claim mismatch in the ID token, expected \"%s\", found \"%s\"", verifyOptions.issuer, token.getIssuer()));
        }

        if (isEmpty(token.getSubject())) {
            throw new TokenValidationException("Subject (sub) claim must be a string present in the ID token");
        }

        final List<String> audience = token.getAudience();
        if (audience == null) {
            throw new TokenValidationException("Audience (aud) claim must be a string or array of strings present in the ID token");
        }
        if (!audience.contains(verifyOptions.audience)) {
            throw new TokenValidationException(String.format("Audience (aud) claim mismatch in the ID token; expected \"%s\" but found \"%s\"", verifyOptions.audience, token.getAudience()));
        }

        final Calendar cal = Calendar.getInstance();
        final Date now = verifyOptions.clock != null ? verifyOptions.clock : cal.getTime();
        final int clockSkew = verifyOptions.clockSkew != null ? verifyOptions.clockSkew : DEFAULT_CLOCK_SKEW;

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

        cal.setTime(token.getIssuedAt());
        cal.add(Calendar.SECOND, -1 * clockSkew);
        Date iatDate = cal.getTime();

        if (now.before(iatDate)) {
            throw new TokenValidationException(String.format("Issued At (iat) claim error in the ID token; current time (%d) is before issued at time (%d)", now.getTime() / 1000, iatDate.getTime() / 1000));
        }


        if (verifyOptions.nonce != null) {
            String nonceClaim = token.getClaim(NONCE_CLAIM).asString();
            if (isEmpty(nonceClaim)) {
                throw new TokenValidationException("Nonce (nonce) claim must be a string present in the ID token");
            }
            if (!verifyOptions.nonce.equals(nonceClaim)) {
                throw new TokenValidationException(String.format("Nonce (nonce) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.nonce, nonceClaim));
            }
        }

        if (audience.size() > 1) {
            String azpClaim = token.getClaim(AZP_CLAIM).asString();
            if (isEmpty(azpClaim)) {
                throw new TokenValidationException("Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values");
            }
            if (!verifyOptions.audience.equals(azpClaim)) {
                throw new TokenValidationException(String.format("Authorized Party (azp) claim mismatch in the ID token; expected \"%s\", found \"%s\"", verifyOptions.audience, azpClaim));
            }
        }

        if (verifyOptions.maxAge != null) {
            Date authTime = token.getClaim(AUTH_TIME_CLAIM).asDate();
            if (authTime == null) {
                throw new TokenValidationException("Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified");
            }

            cal.setTime(authTime);
            cal.add(Calendar.SECOND, verifyOptions.maxAge);
            cal.add(Calendar.SECOND, clockSkew);
            Date authTimeDate = cal.getTime();

            if (now.after(authTimeDate)) {
                throw new TokenValidationException(String.format("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (%d) is after last auth at (%d)", now.getTime() / 1000, authTimeDate.getTime() / 1000));
            }
        }
    }

    public static class Options {
        final String issuer;
        final String audience;
        final SignatureVerifier verifier;
        String nonce;
        private Integer maxAge;
        Integer clockSkew;
        Date clock;

        public Options(@NonNull String issuer, @NonNull String audience, @NonNull SignatureVerifier verifier) {
            this.issuer = issuer;
            this.audience = audience;
            this.verifier = verifier;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public void setMaxAge(Integer maxAge) {
            this.maxAge = maxAge;
        }

        public void setClockSkew(Integer clockSkew) {
            this.clockSkew = clockSkew;
        }

        public void setClock(Date now) {
            this.clock = now;
        }

        Integer getMaxAge() {
            return maxAge;
        }
    }
}
