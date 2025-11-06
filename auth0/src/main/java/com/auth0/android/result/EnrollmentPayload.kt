package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents the payload for an enrollment request.
 * This is a sealed class to handle different types of enrollment payloads.
 */
public sealed class EnrollmentPayload(
    @SerializedName("type")
    public open val type: String
)

public data class PasskeyEnrollmentPayload(
    @SerializedName("connection")
    public val connection: String?,
    @SerializedName("identity_user_id")
    public val identityUserId: String?
) : EnrollmentPayload("passkey")

public object WebAuthnPlatformEnrollmentPayload : EnrollmentPayload("webauthn-platform")

public object WebAuthnRoamingEnrollmentPayload : EnrollmentPayload("webauthn-roaming")

public object TotpEnrollmentPayload : EnrollmentPayload("totp")

public object PushNotificationEnrollmentPayload : EnrollmentPayload("push-notification")

public object RecoveryCodeEnrollmentPayload : EnrollmentPayload("recovery-code")

public data class EmailEnrollmentPayload(
    @SerializedName("email")
    public val email: String
) : EnrollmentPayload("email")

public data class PhoneEnrollmentPayload(
    @SerializedName("phone_number")
    public val phoneNumber: String,
    @SerializedName("preferred_authentication_method")
    public val preferredAuthenticationMethod: String
) : EnrollmentPayload("phone")