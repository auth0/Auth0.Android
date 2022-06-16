package com.auth0.android.provider

import com.auth0.android.provider.SignatureVerifier
import java.util.*

internal class IdTokenVerificationOptions(
    val issuer: String,
    val audience: String,
    val signatureVerifier: SignatureVerifier?
) {
    var organization: String? = null
    var nonce: String? = null
    var maxAge: Int? = null
    var clockSkew: Int? = null
    var clock: Date? = null
}