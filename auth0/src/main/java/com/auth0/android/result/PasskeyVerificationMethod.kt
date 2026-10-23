package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * An identifier whose ownership must be verified with a one-time code before a passkey signup
 * can complete.
 *
 * Returned in [PasskeyRegistrationChallenge.verificationRequired] and
 * [com.auth0.android.authentication.AuthenticationException.passkeyVerificationRequired]. Use it as
 * the key when passing the collected codes in the `verification` map of
 * [com.auth0.android.authentication.AuthenticationAPIClient.signinWithPasskey].
 *
 * ```kotlin
 * val verification = mapOf(PasskeyVerificationMethod.EMAIL to emailCode)
 * ```
 *
 * @property value the value used by the Auth0 Authentication API, e.g. `"email"`.
 */
public enum class PasskeyVerificationMethod(public val value: String) {
    /** The user's email address. */
    @SerializedName("email")
    EMAIL("email"),

    /** The user's phone number. */
    @SerializedName("phone")
    PHONE("phone")
}
