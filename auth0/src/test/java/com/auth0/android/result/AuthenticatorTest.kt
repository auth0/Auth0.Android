package com.auth0.android.result

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for Authenticator and AuthenticatorsList models
 * Part of the SMS OTP MFA POC implementation
 */
class AuthenticatorTest {

    @Test
    fun `should identify SMS authenticator correctly`() {
        val authenticator = Authenticator(
            id = "sms_123",
            authenticatorType = "oob",
            active = true,
            oobChannel = "sms"
        )

        assertTrue(authenticator.isSms)
        assertFalse(authenticator.isOTP)
        assertFalse(authenticator.isEmail)
        assertFalse(authenticator.isRecoveryCode)
    }

    @Test
    fun `should identify OTP authenticator correctly`() {
        val authenticator = Authenticator(
            id = "otp_456",
            authenticatorType = "otp",
            active = true,
            oobChannel = null
        )

        assertTrue(authenticator.isOTP)
        assertFalse(authenticator.isSms)
        assertFalse(authenticator.isEmail)
    }

    @Test
    fun `should identify email authenticator correctly`() {
        val authenticator = Authenticator(
            id = "email_789",
            authenticatorType = "oob",
            active = true,
            oobChannel = "email"
        )

        assertTrue(authenticator.isEmail)
        assertFalse(authenticator.isSms)
        assertFalse(authenticator.isOTP)
    }

    @Test
    fun `should identify recovery code authenticator correctly`() {
        val authenticator = Authenticator(
            id = "recovery_001",
            authenticatorType = "recovery-code",
            active = true,
            oobChannel = null
        )

        assertTrue(authenticator.isRecoveryCode)
        assertFalse(authenticator.isSms)
        assertFalse(authenticator.isOTP)
    }
}

class AuthenticatorsListTest {

    @Test
    fun `should filter SMS authenticators from list`() {
        val authenticators = listOf(
            Authenticator(
                id = "sms_123",
                authenticatorType = "oob",
                active = true,
                oobChannel = "sms"
            ),
            Authenticator(
                id = "otp_456",
                authenticatorType = "otp",
                active = true
            ),
            Authenticator(
                id = "email_789",
                authenticatorType = "oob",
                active = true,
                oobChannel = "email"
            )
        )

        val list = AuthenticatorsList(authenticators)

        assertEquals(1, list.smsAuthenticators.size)
        assertEquals("sms_123", list.smsAuthenticators.first().id)
        assertTrue(list.smsAuthenticators.first().isSms)
    }

    @Test
    fun `should filter OTP authenticators from list`() {
        val authenticators = listOf(
            Authenticator(
                id = "sms_123",
                authenticatorType = "oob",
                active = true,
                oobChannel = "sms"
            ),
            Authenticator(
                id = "otp_456",
                authenticatorType = "otp",
                active = true
            )
        )

        val list = AuthenticatorsList(authenticators)

        assertEquals(1, list.otpAuthenticators.size)
        assertEquals("otp_456", list.otpAuthenticators.first().id)
    }

    @Test
    fun `should get first active SMS authenticator`() {
        val authenticators = listOf(
            Authenticator(
                id = "sms_inactive",
                authenticatorType = "oob",
                active = false,
                oobChannel = "sms"
            ),
            Authenticator(
                id = "sms_active",
                authenticatorType = "oob",
                active = true,
                oobChannel = "sms"
            )
        )

        val list = AuthenticatorsList(authenticators)
        val firstActive = list.firstActiveSmsAuthenticator

        assertNotNull(firstActive)
        assertEquals("sms_active", firstActive?.id)
        assertTrue(firstActive?.active == true)
    }

    @Test
    fun `should return null when no active SMS authenticator exists`() {
        val authenticators = listOf(
            Authenticator(
                id = "sms_inactive",
                authenticatorType = "oob",
                active = false,
                oobChannel = "sms"
            ),
            Authenticator(
                id = "otp_456",
                authenticatorType = "otp",
                active = true
            )
        )

        val list = AuthenticatorsList(authenticators)
        val firstActive = list.firstActiveSmsAuthenticator

        assertNull(firstActive)
    }

    @Test
    fun `should get first active OTP authenticator`() {
        val authenticators = listOf(
            Authenticator(
                id = "otp_inactive",
                authenticatorType = "otp",
                active = false
            ),
            Authenticator(
                id = "otp_active",
                authenticatorType = "otp",
                active = true
            )
        )

        val list = AuthenticatorsList(authenticators)
        val firstActive = list.firstActiveOtpAuthenticator

        assertNotNull(firstActive)
        assertEquals("otp_active", firstActive?.id)
    }

    @Test
    fun `should filter email authenticators from list`() {
        val authenticators = listOf(
            Authenticator(
                id = "email_123",
                authenticatorType = "oob",
                active = true,
                oobChannel = "email"
            ),
            Authenticator(
                id = "sms_456",
                authenticatorType = "oob",
                active = true,
                oobChannel = "sms"
            )
        )

        val list = AuthenticatorsList(authenticators)

        assertEquals(1, list.emailAuthenticators.size)
        assertEquals("email_123", list.emailAuthenticators.first().id)
        assertTrue(list.emailAuthenticators.first().isEmail)
    }

    @Test
    fun `should handle empty authenticators list`() {
        val list = AuthenticatorsList(emptyList())

        assertTrue(list.authenticators.isEmpty())
        assertTrue(list.smsAuthenticators.isEmpty())
        assertTrue(list.otpAuthenticators.isEmpty())
        assertNull(list.firstActiveSmsAuthenticator)
        assertNull(list.firstActiveOtpAuthenticator)
    }

    @Test
    fun `should handle multiple active SMS authenticators`() {
        val authenticators = listOf(
            Authenticator(
                id = "sms_1",
                authenticatorType = "oob",
                active = true,
                oobChannel = "sms"
            ),
            Authenticator(
                id = "sms_2",
                authenticatorType = "oob",
                active = true,
                oobChannel = "sms"
            ),
            Authenticator(
                id = "sms_3",
                authenticatorType = "oob",
                active = true,
                oobChannel = "sms"
            )
        )

        val list = AuthenticatorsList(authenticators)

        assertEquals(3, list.smsAuthenticators.size)
        // Should return the first one
        assertEquals("sms_1", list.firstActiveSmsAuthenticator?.id)
    }
}
