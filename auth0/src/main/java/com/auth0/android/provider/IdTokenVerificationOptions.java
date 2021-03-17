package com.auth0.android.provider;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Date;

class IdTokenVerificationOptions {
    private final String issuer;
    private final String audience;
    private final SignatureVerifier verifier;
    private String organization;
    private String nonce;
    private Integer maxAge;
    private Integer clockSkew;
    private Date clock;

    IdTokenVerificationOptions(@NonNull String issuer, @NonNull String audience, @NonNull SignatureVerifier verifier) {
        this.issuer = issuer;
        this.audience = audience;
        this.verifier = verifier;
    }

    void setNonce(@Nullable String nonce) {
        this.nonce = nonce;
    }

    void setMaxAge(@Nullable Integer maxAge) {
        this.maxAge = maxAge;
    }

    void setClockSkew(@Nullable Integer clockSkew) {
        this.clockSkew = clockSkew;
    }

    void setClock(@Nullable Date now) {
        this.clock = now;
    }

    void setOrganization(@Nullable String organization) {
        this.organization = organization;
    }

    @NonNull
    String getIssuer() {
        return issuer;
    }

    @NonNull
    String getAudience() {
        return audience;
    }

    @NonNull
    SignatureVerifier getSignatureVerifier() {
        return verifier;
    }

    @Nullable
    String getNonce() {
        return nonce;
    }

    @Nullable
    Integer getMaxAge() {
        return maxAge;
    }

    @Nullable
    Integer getClockSkew() {
        return clockSkew;
    }

    @Nullable
    Date getClock() {
        return clock;
    }

    @Nullable
    String getOrganization() {
        return organization;
    }
}
