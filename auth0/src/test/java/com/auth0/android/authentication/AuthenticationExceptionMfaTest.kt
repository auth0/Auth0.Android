package com.auth0.android.authentication

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for AuthenticationException MFA token extraction
 * Part of the SMS OTP MFA POC implementation
 */
class AuthenticationExceptionMfaTest {

    @Test
    fun `should extract mfa_token from error response`() {
        val errorValues = mapOf(
            "error" to "mfa_required",
            "error_description" to "Multifactor authentication required",
            "mfa_token" to "test_mfa_token_12345"
        )

        val exception = AuthenticationException(errorValues, 403)

        assertTrue(exception.isMultifactorRequired)
        assertNotNull(exception.mfaToken)
        assertEquals("test_mfa_token_12345", exception.mfaToken)
    }

    @Test
    fun `should return null when mfa_token is not present`() {
        val errorValues = mapOf(
            "error" to "mfa_required",
            "error_description" to "Multifactor authentication required"
        )

        val exception = AuthenticationException(errorValues, 403)

        assertTrue(exception.isMultifactorRequired)
        assertNull(exception.mfaToken)
    }

    @Test
    fun `should handle non-MFA error without mfa_token`() {
        val errorValues = mapOf(
            "error" to "invalid_grant",
            "error_description" to "Wrong username or password"
        )

        val exception = AuthenticationException(errorValues, 401)

        assertFalse(exception.isMultifactorRequired)
        assertNull(exception.mfaToken)
    }

    @Test
    fun `should identify mfa_required with code variant`() {
        val errorValues = mapOf(
            "error" to "mfa_required",
            "error_description" to "Multifactor authentication required",
            "mfa_token" to "token_abc"
        )

        val exception = AuthenticationException(errorValues, 403)

        assertTrue(exception.isMultifactorRequired)
        assertEquals("token_abc", exception.mfaToken)
    }

    @Test
    fun `should identify a0_mfa_required variant`() {
        val errorValues = mapOf(
            "error" to "a0.mfa_required",
            "error_description" to "MFA is required",
            "mfa_token" to "token_xyz"
        )

        val exception = AuthenticationException(errorValues, 403)

        assertTrue(exception.isMultifactorRequired)
        assertEquals("token_xyz", exception.mfaToken)
    }

    @Test
    fun `should handle mfa_token as different type gracefully`() {
        // In case the API returns mfa_token as non-string (edge case)
        val errorValues = mapOf(
            "error" to "mfa_required",
            "error_description" to "Multifactor authentication required",
            "mfa_token" to 12345 // Integer instead of String
        )

        val exception = AuthenticationException(errorValues, 403)

        assertTrue(exception.isMultifactorRequired)
        // Should return null when type is not String
        assertNull(exception.mfaToken)
    }

    @Test
    fun `should extract mfa_token with real-world response format`() {
        // Simulating actual Auth0 API response
        val errorValues = mapOf(
            "error" to "mfa_required",
            "error_description" to "Multifactor authentication required",
            "mfa_token" to "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyIsImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20vbWZhLyJ9.test",
            "statusCode" to 403
        )

        val exception = AuthenticationException(errorValues, 403)

        assertTrue(exception.isMultifactorRequired)
        assertNotNull(exception.mfaToken)
        assertTrue(exception.mfaToken!!.startsWith("eyJ"))
    }

    @Test
    fun `should handle getValue for mfa_token correctly`() {
        val errorValues = mapOf(
            "error" to "mfa_required",
            "mfa_token" to "test_token"
        )

        val exception = AuthenticationException(errorValues, 403)

        // Test both ways of accessing mfa_token
        assertEquals("test_token", exception.mfaToken)
        assertEquals("test_token", exception.getValue("mfa_token"))
    }

    @Test
    fun `should work with empty error values map`() {
        val errorValues = emptyMap<String, Any>()
        val exception = AuthenticationException(errorValues, 500)

        assertNull(exception.mfaToken)
        assertFalse(exception.isMultifactorRequired)
    }
}
