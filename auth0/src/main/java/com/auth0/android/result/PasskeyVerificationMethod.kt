package com.auth0.android.result

import com.google.gson.TypeAdapter
import com.google.gson.annotations.JsonAdapter
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter

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
 * Identifier types this version of the SDK does not know are kept as-is, so
 * `PasskeyVerificationMethod.fromValue("email") == PasskeyVerificationMethod.EMAIL`.
 *
 * @property value the value used by the Auth0 Authentication API, e.g. `"email"`.
 */
@JsonAdapter(PasskeyVerificationMethod.Adapter::class)
public class PasskeyVerificationMethod private constructor(public val value: String) {

    override fun equals(other: Any?): Boolean =
        this === other || (other is PasskeyVerificationMethod && value == other.value)

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value

    public companion object {
        /** The user's email address. */
        @JvmField
        public val EMAIL: PasskeyVerificationMethod = PasskeyVerificationMethod("email")

        /** The user's phone number. */
        @JvmField
        public val PHONE: PasskeyVerificationMethod = PasskeyVerificationMethod("phone")

        /**
         * Creates a [PasskeyVerificationMethod] from the value used by the Auth0 Authentication API.
         * Unrecognized values are preserved.
         *
         * @param value the raw value, e.g. `"email"`.
         */
        @JvmStatic
        public fun fromValue(value: String): PasskeyVerificationMethod = when (value) {
            EMAIL.value -> EMAIL
            PHONE.value -> PHONE
            else -> PasskeyVerificationMethod(value)
        }
    }

    internal class Adapter : TypeAdapter<PasskeyVerificationMethod>() {
        override fun write(out: JsonWriter, value: PasskeyVerificationMethod) {
            out.value(value.value)
        }

        override fun read(reader: JsonReader): PasskeyVerificationMethod =
            fromValue(reader.nextString())
    }
}
