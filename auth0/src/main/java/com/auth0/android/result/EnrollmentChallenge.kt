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
    public abstract val authSession: String

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
    @SerializedName("id")
    override val id: String,
    @SerializedName("auth_session")
    override val authSession: String
) : EnrollmentChallenge()

public data class TotpEnrollmentChallenge(
    @SerializedName("id")
    override val id: String,
    @SerializedName("auth_session")
    override val authSession: String,
    @SerializedName("barcode_uri")
    public val barcodeUri: String,
    @SerializedName("manual_input_code")
    public val manualInputCode: String?
) : EnrollmentChallenge()

public data class RecoveryCodeEnrollmentChallenge(
    @SerializedName("id")
    override val id: String,
    @SerializedName("auth_session")
    override val authSession: String,
    @SerializedName("recovery_code")
    public val recoveryCode: String
) : EnrollmentChallenge()