package com.auth0.android.result

import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.annotations.JsonAdapter
import com.google.gson.annotations.SerializedName
import java.lang.reflect.Type

@JsonAdapter(EnrollmentChallenge.Deserializer::class)
public sealed class EnrollmentChallenge(
    @SerializedName("id")
    public open val id: String?,
    @SerializedName("auth_session")
    public open val authSession: String
) {
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
                else -> MfaEnrollmentChallenge::class.java
            }
            return context.deserialize(jsonObject, targetClass)
        }
    }
}

public data class MfaEnrollmentChallenge(
    public override val id: String,
    public override val authSession: String
) : EnrollmentChallenge(id, authSession)

public data class TotpEnrollmentChallenge(
    public override val id: String,
    public override val authSession: String,
    @SerializedName("barcode_uri")
    public val barcodeUri: String,
    @SerializedName("manual_input_code")
    public val manualInputCode: String
) : EnrollmentChallenge(id, authSession)

public data class RecoveryCodeEnrollmentChallenge(
    public override val id: String,
    public override val authSession: String,
    @SerializedName("recovery_code")
    public val recoveryCode: String
) : EnrollmentChallenge(id, authSession)

public data class PublicKeyCredentialCreationOptions(
    @SerializedName("rp")
    public val rp: RelyingParty,
    @SerializedName("user")
    public val user: User,
    @SerializedName("challenge")
    public val challenge: String,
    @SerializedName("pubKeyCredParams")
    public val pubKeyCredParams: List<PubKeyCredParam>,
    @SerializedName("timeout")
    public val timeout: Long?,
    @SerializedName("authenticatorSelection")
    public val authenticatorSelection: AuthenticatorSelection?
) {
    public data class RelyingParty(
        @SerializedName("id")
        public val id: String,
        @SerializedName("name")
        public val name: String
    )
    public data class User(
        @SerializedName("id")
        public val id: String,
        @SerializedName("name")
        public val name: String,
        @SerializedName("displayName")
        public val displayName: String
    )
    public data class PubKeyCredParam(
        @SerializedName("type")
        public val type: String,
        @SerializedName("alg")
        public val alg: Int
    )
    public data class AuthenticatorSelection(
        @SerializedName("userVerification")
        public val userVerification: String?,
        @SerializedName("residentKey")
        public val residentKey: String?
    )
}