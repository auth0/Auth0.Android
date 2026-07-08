package com.auth0.android.result

import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.annotations.JsonAdapter
import com.google.gson.annotations.SerializedName
import java.lang.reflect.Type

@JsonAdapter(EnrollmentChallenge.Deserializer::class)
public sealed class EnrollmentChallenge {
    public abstract val id: String?
    public abstract val authSession: String?
    public open val oobCode: String? = null 

    internal class Deserializer : JsonDeserializer<EnrollmentChallenge> {
        override fun deserialize(
            json: JsonElement,
            typeOfT: Type,
            context: JsonDeserializationContext
        ): EnrollmentChallenge? {
            val jsonObject = json.asJsonObject
            val targetClass = when {
                jsonObject.has("barcode_uri") -> TotpEnrollmentChallenge::class.java
                jsonObject.has("recovery_code") -> RecoveryCodeEnrollmentChallenge::class.java
                jsonObject.has("authn_params_public_key") -> PasskeyEnrollmentChallenge::class.java
                jsonObject.has("oob_code") -> OobEnrollmentChallenge::class.java
                jsonObject.has("policy") -> PasswordEnrollmentChallenge::class.java
                else -> MfaEnrollmentChallenge::class.java
            }
            return context.deserialize(jsonObject, targetClass)
        }
    }
}

public data class MfaEnrollmentChallenge(
    @SerializedName("id")
    override val id: String,
    @SerializedName("auth_session")
    override val authSession: String
) : EnrollmentChallenge()

/**
 * Enrollment challenge for OOB factors (SMS/Email) that includes the oob_code
 * needed for verification.
 */
public data class OobEnrollmentChallenge(
    @SerializedName("id")
    override val id: String?,
    @SerializedName("auth_session")
    override val authSession: String?,
    @SerializedName("oob_code")
    override val oobCode: String?,
    @SerializedName("binding_method")
    public val bindingMethod: String? = null
) : EnrollmentChallenge()

/**
 * Enrollment challenge for TOTP (authenticator app) and Push factors, returned by both
 * the MFA `/mfa/associate` endpoint and the My Account `/authentication-methods` endpoint.
 *
 * The two endpoints return different field sets, so every field except [barcodeUri] is
 * optional:
 *  - `/mfa/associate` (ROPG MFA flow) returns [authenticatorType], [secret], [barcodeUri]
 *    and [recoveryCodes]. It does NOT return `id`, `auth_session` or `manual_input_code`.
 *  - `/authentication-methods` (My Account) returns [id], [authSession], [barcodeUri] and
 *    [manualInputCode].
 *
 * [secret] and [manualInputCode] both carry the human-readable key for manual entry into an
 * authenticator app; only one is populated depending on the endpoint. The [barcodeUri]
 * (`otpauth://` URI) is always present and embeds the same secret.
 */
public data class TotpEnrollmentChallenge(
    @SerializedName("id")
    override val id: String? = null,
    @SerializedName("auth_session")
    override val authSession: String? = null,
    @SerializedName("barcode_uri")
    public val barcodeUri: String,
    @SerializedName("manual_input_code")
    public val manualInputCode: String? = null,
    @SerializedName("authenticator_type")
    public val authenticatorType: String? = null,
    @SerializedName("secret")
    public val secret: String? = null,
    @SerializedName("recovery_codes")
    public val recoveryCodes: List<String>? = null
) : EnrollmentChallenge()

public data class RecoveryCodeEnrollmentChallenge(
    @SerializedName("id")
    override val id: String,
    @SerializedName("auth_session")
    override val authSession: String,
    @SerializedName("recovery_code")
    public val recoveryCode: String
) : EnrollmentChallenge()

/**
 * Enrollment challenge for a password authentication method. Includes the [policy] the new password
 * must satisfy, so the app can guide the user before confirming the enrollment.
 */
public data class PasswordEnrollmentChallenge(
    @SerializedName("id")
    override val id: String,
    @SerializedName("auth_session")
    override val authSession: String,
    @SerializedName("policy")
    public val policy: PasswordPolicy
) : EnrollmentChallenge()