package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents the payload for a verification request, such as providing an OTP code.
 */
public data class VerifyOtpPayload(
    @SerializedName("otp_code")
    public val otpCode: String
)