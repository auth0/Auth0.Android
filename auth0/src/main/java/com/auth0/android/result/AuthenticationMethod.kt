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
public sealed class AuthenticationMethod {
    public abstract val id: String
    public abstract val type: String
    public abstract val createdAt: String
    public abstract val usage: List<String>

    internal class Deserializer : JsonDeserializer<AuthenticationMethod> {
        override fun deserialize(
            json: JsonElement,
            typeOfT: Type,
            context: JsonDeserializationContext
        ): AuthenticationMethod? {
            val jsonObject = json.asJsonObject
            val type = jsonObject.get("type")?.asString
            val targetClass = when (type) {
                "password" -> PasswordAuthenticationMethod::class.java
                "passkey" -> PasskeyAuthenticationMethod::class.java
                "recovery-code" -> RecoveryCodeAuthenticationMethod::class.java
                "push-notification" -> PushNotificationAuthenticationMethod::class.java
                "totp" -> TotpAuthenticationMethod::class.java
                "webauthn-platform" -> WebAuthnPlatformAuthenticationMethod::class.java
                "webauthn-roaming" -> WebAuthnRoamingAuthenticationMethod::class.java
                "phone" -> PhoneAuthenticationMethod::class.java
                "email" -> EmailAuthenticationMethod::class.java
                else -> null
            }
            return context.deserialize(jsonObject, targetClass)
        }
    }
}

public data class PasswordAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("identity_user_id")
    public val identityUserId: String?,
    @SerializedName("last_password_reset")
    public val lastPasswordReset: String?
) : AuthenticationMethod()

public data class PasskeyAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("credential_backed_up")
    public val credentialBackedUp: Boolean?,
    @SerializedName("credential_device_type")
    public val credentialDeviceType: String?,
    @SerializedName("identity_user_id")
    public val identityUserId: String?,
    @SerializedName("key_id")
    public val keyId: String?,
    @SerializedName("public_key")
    public val publicKey: String?,
    @SerializedName("transports")
    public val transports: List<String>?,
    @SerializedName("user_agent")
    public val userAgent: String?,
    @SerializedName("user_handle")
    public val userHandle: String?
) : AuthenticationMethod()

public sealed class MfaAuthenticationMethod : AuthenticationMethod() {
    public abstract val confirmed: Boolean?
}

public data class RecoveryCodeAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("confirmed") override val confirmed: Boolean?
) : MfaAuthenticationMethod()

public data class PushNotificationAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("confirmed") override val confirmed: Boolean?,
    @SerializedName("name")
    public val name: String?
) : MfaAuthenticationMethod()

public data class TotpAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("confirmed") override val confirmed: Boolean?,
    @SerializedName("name")
    public val name: String?
) : MfaAuthenticationMethod()

public sealed class WebAuthnAuthenticationMethod : MfaAuthenticationMethod() {
    public abstract val name: String?
    public abstract val keyId: String?
    public abstract val publicKey: String?
}

public data class WebAuthnPlatformAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("confirmed") override val confirmed: Boolean?,
    @SerializedName("name") override val name: String?,
    @SerializedName("key_id") override val keyId: String?,
    @SerializedName("public_key") override val publicKey: String?
) : WebAuthnAuthenticationMethod()

public data class WebAuthnRoamingAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("confirmed") override val confirmed: Boolean?,
    @SerializedName("name") override val name: String?,
    @SerializedName("key_id") override val keyId: String?,
    @SerializedName("public_key") override val publicKey: String?
) : WebAuthnAuthenticationMethod()

public data class PhoneAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("confirmed") override val confirmed: Boolean?,
    @SerializedName("name")
    public val name: String?,
    @SerializedName("phone_number")
    public val phoneNumber: String?,
    @SerializedName("preferred_authentication_method")
    public val preferredAuthenticationMethod: String?
) : MfaAuthenticationMethod()

public data class EmailAuthenticationMethod(
    @SerializedName("id") override val id: String,
    @SerializedName("type") override val type: String,
    @SerializedName("created_at") override val createdAt: String,
    @SerializedName("usage") override val usage: List<String>,
    @SerializedName("confirmed") override val confirmed: Boolean?,
    @SerializedName("name")
    public val name: String?,
    @SerializedName("email")
    public val email: String?
) : MfaAuthenticationMethod()