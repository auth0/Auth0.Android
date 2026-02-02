package com.auth0.android.authentication

/**
 * Represents the type of MFA enrollment to perform.
 *
 * Use one of the subclasses to specify the enrollment method when calling [MfaApiClient.enroll].
 *
 * ## Usage
 *
 * ```kotlin
 * // Phone (SMS) enrollment
 * mfaClient.enroll(MfaEnrollmentType.Phone("+12025550135"))
 *
 * // Email enrollment
 * mfaClient.enroll(MfaEnrollmentType.Email("user@example.com"))
 *
 * // TOTP (Authenticator app) enrollment
 * mfaClient.enroll(MfaEnrollmentType.Otp)
 *
 * // Push notification enrollment
 * mfaClient.enroll(MfaEnrollmentType.Push)
 * ```
 *
 * @see MfaApiClient.enroll
 */
public sealed class MfaEnrollmentType {
    /**
     * Enrolls a phone number for SMS-based MFA.
     *
     * An SMS with a verification code will be sent to the specified phone number.
     *
     * @property phoneNumber The phone number to enroll, including country code (e.g., `+12025550135`).
     */
    public data class Phone(val phoneNumber: String) : MfaEnrollmentType()

    /**
     * Enrolls an email address for email-based MFA.
     *
     * Verification codes will be sent to the specified email address during authentication.
     *
     * @property email The email address to enroll for MFA.
     */
    public data class Email(val email: String) : MfaEnrollmentType()

    /**
     * Enrolls a time-based one-time password (TOTP) authenticator for MFA.
     *
     * The response will contain a QR code and secret that can be scanned by authenticator apps
     * like Google Authenticator or Authy.
     */
    public object Otp : MfaEnrollmentType()

    /**
     * Enrolls push notification as an MFA factor.
     *
     * Users will receive authentication requests via push notifications on their enrolled device
     * using Auth0 Guardian.
     */
    public object Push : MfaEnrollmentType()
}

/**
 * Represents the type of MFA verification to perform.
 *
 * Use one of the subclasses to specify the verification method when calling [MfaApiClient.verify].
 *
 * ## Usage
 *
 * ```kotlin
 * // Verify with OOB code (SMS/Email)
 * mfaClient.verify(MfaVerificationType.Oob(oobCode = "Fe26.2*...", bindingCode = "123456"))
 *
 * // Verify with OTP code (Authenticator app)
 * mfaClient.verify(MfaVerificationType.Otp(otp = "123456"))
 *
 * // Verify with recovery code
 * mfaClient.verify(MfaVerificationType.RecoveryCode(code = "RECOVERY_CODE_123"))
 * ```
 *
 * @see MfaApiClient.verify
 */
public sealed class MfaVerificationType {
    /**
     * Verifies an MFA challenge using an out-of-band (OOB) code.
     *
     * This is used after receiving an SMS or email challenge. The oobCode is obtained from the
     * challenge response, and the bindingCode is the verification code entered by the user.
     *
     * @property oobCode The out-of-band code from the challenge response.
     * @property bindingCode Optional binding code (the code sent to the user's phone/email).
     */
    public data class Oob(
        val oobCode: String,
        val bindingCode: String? = null
    ) : MfaVerificationType()

    /**
     * Verifies an MFA challenge using a one-time password (OTP) code.
     *
     * This is used when the user has an authenticator app (like Google Authenticator or Authy)
     * that generates time-based codes.
     *
     * @property otp The 6-digit one-time password code from the authenticator app.
     */
    public data class Otp(val otp: String) : MfaVerificationType()

    /**
     * Verifies an MFA challenge using a recovery code.
     *
     * Recovery codes are used when users don't have access to their primary MFA factor.
     * Upon successful verification, a new recovery code is returned in the credentials.
     *
     * @property code The recovery code provided during MFA enrollment.
     */
    public data class RecoveryCode(val code: String) : MfaVerificationType()
}
