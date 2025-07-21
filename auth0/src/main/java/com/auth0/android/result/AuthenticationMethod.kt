package com.auth0.android.result

import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.annotations.JsonAdapter
import com.google.gson.annotations.SerializedName
import java.lang.reflect.Type

public data class AuthenticationMethods(
    @SerializedName("authentication_methods")
    public val authenticationMethods: List<AuthenticationMethod>
)

@JsonAdapter(AuthenticationMethod.Deserializer::class)
public sealed class AuthenticationMethod(
    @SerializedName("id")
    public open val id: String,
    @SerializedName("type")
    public open val type: String,
    @SerializedName("created_at")
    public open val createdAt: String,
    @SerializedName("usage")
    public open val usage: List<String>
) {
    internal class Deserializer : JsonDeserializer<AuthenticationMethod> {
        override fun deserialize(
            json: JsonElement,
            typeOfT: Type,
            context: JsonDeserializationContext
        ): AuthenticationMethod? {
            val jsonObject = json.asJsonObject
            val type = jsonObject.get("type")?.asString ?: return null

            val targetClass = when (type) {
                "password" -> PasswordAuthenticationMethod::class.java
                "passkey" -> PasskeyAuthenticationMethod::class.java
                "recovery-code" -> MfaRecoveryCodeAuthenticationMethod::class.java
                "push-notification" -> MfaPushNotificationAuthenticationMethod::class.java
                "totp" -> MfaTotpAuthenticationMethod::class.java
                "webauthn-platform" -> WebAuthnPlatformAuthenticationMethod::class.java
                "webauthn-roaming" -> WebAuthnRoamingAuthenticationMethod::class.java
                "phone" -> PhoneAuthenticationMethod::class.java
                "email" -> EmailAuthenticationMethod::class.java
                else -> UnknownAuthenticationMethod::class.java
            }
            return context.deserialize(jsonObject, targetClass)
        }
    }
}

public data class UnknownAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>
) : AuthenticationMethod(id, type, createdAt, usage)

public data class PasswordAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    @SerializedName("identity_user_id")
    public val identityUserId: String,
    @SerializedName("last_password_reset")
    public val lastPasswordReset: String?
) : AuthenticationMethod(id, type, createdAt, usage)

public abstract class MfaAuthenticationMethod(
    id: String,
    type: String,
    createdAt: String,
    usage: List<String>,
    @SerializedName("confirmed")
    public open val confirmed: Boolean,
    @SerializedName("name")
    public open val name: String?
) : AuthenticationMethod(id, type, createdAt, usage)

public data class MfaRecoveryCodeAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    public override val confirmed: Boolean,
    public override val name: String?
) : MfaAuthenticationMethod(id, type, createdAt, usage, confirmed, name)

public data class MfaPushNotificationAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    public override val confirmed: Boolean,
    public override val name: String?
) : MfaAuthenticationMethod(id, type, createdAt, usage, confirmed, name)

public data class MfaTotpAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    public override val confirmed: Boolean,
    public override val name: String?
) : MfaAuthenticationMethod(id, type, createdAt, usage, confirmed, name)

public data class WebAuthnPlatformAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    public override val confirmed: Boolean,
    public override val name: String?,
    @SerializedName("key_id")
    public val keyId: String,
    @SerializedName("public_key")
    public val publicKey: String
) : MfaAuthenticationMethod(id, type, createdAt, usage, confirmed, name)

public data class WebAuthnRoamingAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    public override val confirmed: Boolean,
    public override val name: String?,
    @SerializedName("key_id")
    public val keyId: String,
    @SerializedName("public_key")
    public val publicKey: String
) : MfaAuthenticationMethod(id, type, createdAt, usage, confirmed, name)

public data class PhoneAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    public override val confirmed: Boolean,
    public override val name: String?,
    @SerializedName("phone_number")
    public val phoneNumber: String,
    @SerializedName("preferred_authentication_method")
    public val preferredAuthenticationMethod: String
) : MfaAuthenticationMethod(id, type, createdAt, usage, confirmed, name)

public data class EmailAuthenticationMethod(
    public override val id: String,
    public override val type: String,
    public override val createdAt: String,
    public override val usage: List<String>,
    public override val confirmed: Boolean,
    public override val name: String?,
    @SerializedName("email")
    public val email: String
) : MfaAuthenticationMethod(id, type, createdAt, usage, confirmed, name)