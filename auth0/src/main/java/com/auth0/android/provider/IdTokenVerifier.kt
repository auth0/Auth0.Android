package com.auth0.android.provider

import com.auth0.android.request.internal.Jwt
import android.text.TextUtils
import java.util.*

internal class IdTokenVerifier {
    /**
     * Verifies a provided ID Token follows the OIDC specification.
     * See https://openid.net/specs/openid-connect-core-1_0-final.html#IDTokenValidation
     *
     * @param token         the ID Token to verify.
     * @param verifyOptions the verification options, like audience, issuer, algorithm.
     * @throws TokenValidationException If the ID Token is null, its signing algorithm not supported, its signature invalid or one of its claim invalid.
     */
    @Throws(TokenValidationException::class)
    fun verify(token: Jwt, verifyOptions: IdTokenVerificationOptions, verifySignature: Boolean) {
        if (verifySignature) {
            verifyOptions.signatureVerifier?.verify(token) ?: throw TokenValidationException("Signature Verifier should not be null")
        }
        if (TextUtils.isEmpty(token.issuer)) {
            throw TokenValidationException("Issuer (iss) claim must be a string present in the ID token")
        }
        if (token.issuer != verifyOptions.issuer) {
            throw TokenValidationException(
                String.format(
                    "Issuer (iss) claim mismatch in the ID token, expected \"%s\", found \"%s\"",
                    verifyOptions.issuer,
                    token.issuer
                )
            )
        }
        if (TextUtils.isEmpty(token.subject)) {
            throw TokenValidationException("Subject (sub) claim must be a string present in the ID token")
        }
        val audience = token.audience
        if (audience.isEmpty()) {
            throw TokenValidationException("Audience (aud) claim must be a string or array of strings present in the ID token")
        }
        if (!audience.contains(verifyOptions.audience)) {
            throw TokenValidationException(
                String.format(
                    "Audience (aud) claim mismatch in the ID token; expected \"%s\" but was not one of \"%s\"",
                    verifyOptions.audience,
                    token.audience
                )
            )
        }
        val cal = Calendar.getInstance()
        val now = if (verifyOptions.clock != null) verifyOptions.clock else cal.time
        val clockSkew =
            if (verifyOptions.clockSkew != null) verifyOptions.clockSkew!! else DEFAULT_CLOCK_SKEW
        if (token.expiresAt == null) {
            throw TokenValidationException("Expiration Time (exp) claim must be a number present in the ID token")
        }
        cal.time = token.expiresAt
        cal.add(Calendar.SECOND, clockSkew)
        val expDate = cal.time
        if (now!!.after(expDate)) {
            throw TokenValidationException(
                String.format(
                    "Expiration Time (exp) claim error in the ID token; current time (%d) is after expiration time (%d)",
                    now.time / 1000,
                    expDate.time / 1000
                )
            )
        }
        if (token.issuedAt == null) {
            throw TokenValidationException("Issued At (iat) claim must be a number present in the ID token")
        }
        if (verifyOptions.nonce != null) {
            val nonceClaim = token.nonce
            if (TextUtils.isEmpty(nonceClaim)) {
                throw TokenValidationException("Nonce (nonce) claim must be a string present in the ID token")
            }
            if (verifyOptions.nonce != nonceClaim) {
                throw TokenValidationException(
                    String.format(
                        "Nonce (nonce) claim mismatch in the ID token; expected \"%s\", found \"%s\"",
                        verifyOptions.nonce,
                        nonceClaim
                    )
                )
            }
        }
        if (verifyOptions.organization != null) {
            val orgClaim = token.organizationId
            if (TextUtils.isEmpty(orgClaim)) {
                throw TokenValidationException("Organization Id (org_id) claim must be a string present in the ID token")
            }
            if (verifyOptions.organization != orgClaim) {
                throw TokenValidationException(
                    String.format(
                        "Organization Id (org_id) claim mismatch in the ID token; expected \"%s\", found \"%s\"",
                        verifyOptions.organization,
                        orgClaim
                    )
                )
            }
        }
        if (audience.size > 1) {
            val azpClaim = token.authorizedParty
            if (TextUtils.isEmpty(azpClaim)) {
                throw TokenValidationException("Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values")
            }
            if (verifyOptions.audience != azpClaim) {
                throw TokenValidationException(
                    String.format(
                        "Authorized Party (azp) claim mismatch in the ID token; expected \"%s\", found \"%s\"",
                        verifyOptions.audience,
                        azpClaim
                    )
                )
            }
        }
        if (verifyOptions.maxAge != null) {
            val authTime = token.authenticationTime
                ?: throw TokenValidationException("Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified")
            cal.time = authTime
            cal.add(Calendar.SECOND, verifyOptions.maxAge!!)
            cal.add(Calendar.SECOND, clockSkew)
            val authTimeDate = cal.time
            if (now.after(authTimeDate)) {
                throw TokenValidationException(
                    String.format(
                        "Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (%d) is after last auth at (%d)",
                        now.time / 1000,
                        authTimeDate.time / 1000
                    )
                )
            }
        }
    }

    companion object {
        private const val DEFAULT_CLOCK_SKEW = 60 // 1 min = 60 sec
    }
}