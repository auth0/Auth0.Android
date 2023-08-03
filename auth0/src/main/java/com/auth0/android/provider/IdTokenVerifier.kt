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
            verifyOptions.signatureVerifier?.verify(token) ?: throw SignatureVerifierMissingException()
        }
        if (TextUtils.isEmpty(token.issuer)) {
            throw IssClaimMissingException()
        }
        if (token.issuer != verifyOptions.issuer) {
            throw throw IssClaimMismatchException(verifyOptions.issuer, token.issuer)
        }
        if (TextUtils.isEmpty(token.subject)) {
            throw SubClaimMissingException()
        }
        val audience = token.audience
        if (audience.isEmpty()) {
            throw AudClaimMissingException()
        }
        if (!audience.contains(verifyOptions.audience)) {
            throw AudClaimMismatchException(verifyOptions.audience, token.audience)
        }
        val cal = Calendar.getInstance()
        val now = if (verifyOptions.clock != null) verifyOptions.clock else cal.time
        val clockSkew =
            if (verifyOptions.clockSkew != null) verifyOptions.clockSkew!! else DEFAULT_CLOCK_SKEW
        if (token.expiresAt == null) {
            throw ExpClaimMissingException()
        }
        cal.time = token.expiresAt
        cal.add(Calendar.SECOND, clockSkew)
        val expDate = cal.time
        if (now!!.after(expDate)) {
            throw IdTokenExpiredException(now.time / 1000, expDate.time / 1000)
        }
        if (token.issuedAt == null) {
            throw IatClaimMissingException()
        }
        if (verifyOptions.nonce != null) {
            val nonceClaim = token.nonce
            if (TextUtils.isEmpty(nonceClaim)) {
                throw NonceClaimMissingException()
            }
            if (verifyOptions.nonce != nonceClaim) {
                throw NonceClaimMismatchException(verifyOptions.nonce, nonceClaim)
            }
        }
        verifyOptions.organization?.let {organizationInput ->
            if(organizationInput.startsWith("org_")) {
                val orgClaim = token.organizationId
                if (TextUtils.isEmpty(orgClaim)) {
                    throw OrgClaimMissingException()
                }
                if (organizationInput != orgClaim) {
                    throw OrgClaimMismatchException(organizationInput, orgClaim)
                }
            } else {
                val orgNameClaim = token.organizationName
                if (TextUtils.isEmpty(orgNameClaim)) {
                    throw OrgNameClaimMissingException()
                }
                if (organizationInput.lowercase() != orgNameClaim) {
                    throw OrgNameClaimMismatchException(organizationInput, orgNameClaim)
                }
            }
        }
        if (audience.size > 1) {
            val azpClaim = token.authorizedParty
            if (TextUtils.isEmpty(azpClaim)) {
                throw AzpClaimMissingException()
            }
            if (verifyOptions.audience != azpClaim) {
                throw AzpClaimMismatchException(
                        verifyOptions.audience,
                        azpClaim
                    )
            }
        }
        if (verifyOptions.maxAge != null) {
            val authTime = token.authenticationTime
                ?: throw AuthTimeClaimMissingException()
            cal.time = authTime
            cal.add(Calendar.SECOND, verifyOptions.maxAge!!)
            cal.add(Calendar.SECOND, clockSkew)
            val authTimeDate = cal.time
            if (now.after(authTimeDate)) {
                throw AuthTimeClaimMismatchException(now.time / 1000, authTimeDate.time / 1000)
            }
        }
    }

    companion object {
        private const val DEFAULT_CLOCK_SKEW = 60 // 1 min = 60 sec
    }
}