package com.auth0.android.result

import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.annotations.JsonAdapter
import com.google.gson.annotations.SerializedName
import java.lang.reflect.Type

/**
 * The current user's profile, as returned by the My Account API `/me/v1/profile` endpoint.
 *
 * Every property is nullable: the server omits fields that are not set for the user, and
 * any field can be trimmed from the response by using
 * [com.auth0.android.myaccount.request.GetUserProfileOptions.fields].
 *
 * [userId], [emailVerified] and [phoneVerified] are read-only: they can't be changed with
 * [com.auth0.android.myaccount.request.UpdateUserProfileRequest].
 */
public data class MyAccountProfile(
    @SerializedName("user_id")
    public val userId: String? = null,
    @SerializedName("given_name")
    public val givenName: String? = null,
    @SerializedName("family_name")
    public val familyName: String? = null,
    @SerializedName("name")
    public val name: String? = null,
    @SerializedName("nickname")
    public val nickname: String? = null,
    @SerializedName("picture")
    public val picture: String? = null,
    @SerializedName("email")
    public val email: String? = null,
    @SerializedName("email_verified")
    public val emailVerified: Boolean? = null,
    @SerializedName("phone_number")
    public val phoneNumber: String? = null,
    @SerializedName("phone_verified")
    public val phoneVerified: Boolean? = null,
    @SerializedName("username")
    public val username: String? = null,
    @SerializedName("created_at")
    public val createdAt: String? = null,
    @SerializedName("updated_at")
    public val updatedAt: String? = null,
    /**
     * Describes, per field, whether it can be edited by the user and why. Keyed by a JSON
     * Pointer to the field, e.g. `/given_name`.
     * Absent when `profile_policy` is not part of the response, see
     * [com.auth0.android.myaccount.request.GetUserProfileOptions].
     */
    @SerializedName("profile_policy")
    public val profilePolicy: Map<String, ProfileFieldPolicy>? = null
)

/**
 * Describes whether a profile field can be edited by the user and why.
 */
@JsonAdapter(ProfileFieldPolicy.Deserializer::class)
public data class ProfileFieldPolicy(
    /**
     * Whether the field is editable. Null if the server returned a value unknown to this SDK version.
     */
    @SerializedName("access")
    public val access: ProfileFieldAccess? = null,
    /**
     * Where the field's value comes from. Null if the server returned a value unknown to this SDK version.
     */
    @SerializedName("source")
    public val source: ProfileFieldSource? = null,
    /**
     * Machine-readable reason a field is read-only, e.g. `managed_by_identity_provider`.
     * Only set when [access] is read-only. New values may be added by the server.
     */
    @SerializedName("reason")
    public val reason: String? = null
) {

    // Maps unknown access/source values to null instead of failing to parse the profile.
    internal class Deserializer : JsonDeserializer<ProfileFieldPolicy> {
        override fun deserialize(
            json: JsonElement,
            typeOfT: Type,
            context: JsonDeserializationContext
        ): ProfileFieldPolicy {
            val jsonObject = json.asJsonObject
            return ProfileFieldPolicy(
                access = ProfileFieldAccess.fromValue(jsonObject.stringOrNull("access")),
                source = ProfileFieldSource.fromValue(jsonObject.stringOrNull("source")),
                reason = jsonObject.stringOrNull("reason")
            )
        }

        private fun JsonObject.stringOrNull(key: String): String? =
            get(key)?.takeIf { it.isJsonPrimitive }?.asString
    }
}

/**
 * Whether a profile field can be edited by the user.
 */
public enum class ProfileFieldAccess(public val value: String) {
    READ_ONLY("read_only"),
    READ_WRITE("read_write");

    internal companion object {
        fun fromValue(value: String?): ProfileFieldAccess? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where a profile field's value comes from.
 */
public enum class ProfileFieldSource(public val value: String) {
    USER("user"),
    IDP("idp"),
    SYSTEM("system");

    internal companion object {
        fun fromValue(value: String?): ProfileFieldSource? = entries.firstOrNull { it.value == value }
    }
}
