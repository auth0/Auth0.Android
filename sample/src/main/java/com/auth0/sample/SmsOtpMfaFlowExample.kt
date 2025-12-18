package com.auth0.sample

import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.result.AuthenticatorsList
import com.auth0.android.result.Challenge
import com.auth0.android.result.Credentials

/**
 * POC implementation demonstrating SMS OTP MFA flow for flexible grant support.
 *
 * This example shows how to:
 * 1. Attempt login with username/password
 * 2. Handle mfa_required error
 * 3. List available authenticators
 * 4. Trigger SMS OTP challenge
 * 5. Verify SMS OTP code
 * 6. Complete authentication
 *
 * Based on the PRD for flexible grant factor support and aligned with iOS implementation.
 */
class SmsOtpMfaFlowExample {

    private lateinit var auth0: Auth0
    private lateinit var authClient: AuthenticationAPIClient

    fun initialize(clientId: String, domain: String) {
        auth0 = Auth0.getInstance(clientId, domain)
        authClient = AuthenticationAPIClient(auth0)
    }

    /**
     * Step 1: Initial login attempt with username and password
     * This will fail with mfa_required error if MFA is enabled
     */
    fun loginWithUsernamePassword(
        username: String,
        password: String,
        realm: String,
        onMfaRequired: (mfaToken: String) -> Unit,
        onSuccess: (Credentials) -> Unit,
        onError: (AuthenticationException) -> Unit
    ) {
        authClient.login(username, password, realm)
            .validateClaims()
            .start(object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    // Login succeeded without MFA
                    onSuccess(result)
                }

                override fun onFailure(error: AuthenticationException) {
                    if (error.isMultifactorRequired) {
                        // MFA is required - extract mfa_token and proceed to MFA flow
                        val mfaToken = error.mfaToken
                        if (mfaToken != null) {
                            onMfaRequired(mfaToken)
                        } else {
                            onError(AuthenticationException("mfa_token not found in error response"))
                        }
                    } else {
                        // Other authentication error
                        onError(error)
                    }
                }
            })
    }

    /**
     * Step 2: List available authenticators for the user
     * Filter for SMS authenticators
     */
    fun listSmsAuthenticators(
        mfaToken: String,
        onSuccess: (AuthenticatorsList) -> Unit,
        onError: (AuthenticationException) -> Unit
    ) {
        authClient.listAuthenticators(mfaToken)
            .start(object : Callback<AuthenticatorsList, AuthenticationException> {
                override fun onSuccess(result: AuthenticatorsList) {
                    onSuccess(result)
                }

                override fun onFailure(error: AuthenticationException) {
                    onError(error)
                }
            })
    }

    /**
     * Step 3: Trigger SMS OTP challenge
     * This will send an SMS with the OTP code to the user's phone
     */
    fun triggerSmsChallenge(
        mfaToken: String,
        authenticatorId: String,
        onSuccess: (Challenge) -> Unit,
        onError: (AuthenticationException) -> Unit
    ) {
        authClient.multifactorChallenge(
            mfaToken = mfaToken,
            challengeType = "oob",
            authenticatorId = authenticatorId
        ).start(object : Callback<Challenge, AuthenticationException> {
            override fun onSuccess(result: Challenge) {
                // Challenge initiated successfully
                // SMS should be sent to user's phone
                onSuccess(result)
            }

            override fun onFailure(error: AuthenticationException) {
                onError(error)
            }
        })
    }

    /**
     * Step 4: Verify SMS OTP code and complete authentication
     * Use the OTP code entered by the user
     */
    fun verifySmsOtp(
        mfaToken: String,
        oobCode: String,
        bindingCode: String,
        onSuccess: (Credentials) -> Unit,
        onError: (AuthenticationException) -> Unit
    ) {
        authClient.loginWithOOB(
            mfaToken = mfaToken,
            oobCode = oobCode,
            bindingCode = bindingCode
        )
            .validateClaims()
            .start(object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    // Authentication completed successfully with MFA
                    onSuccess(result)
                }

                override fun onFailure(error: AuthenticationException) {
                    if (error.isMultifactorCodeInvalid) {
                        // Invalid OTP code
                        onError(AuthenticationException("Invalid or expired OTP code"))
                    } else {
                        onError(error)
                    }
                }
            })
    }

    /**
     * Complete SMS OTP MFA flow demonstration
     * This orchestrates all steps in sequence
     */
    fun completeSmsOtpMfaFlow(
        username: String,
        password: String,
        realm: String,
        otpCode: String,
        onSuccess: (Credentials) -> Unit,
        onError: (AuthenticationException) -> Unit
    ) {
        // Step 1: Initial login
        loginWithUsernamePassword(
            username = username,
            password = password,
            realm = realm,
            onMfaRequired = { mfaToken ->
                // Step 2: List authenticators
                listSmsAuthenticators(
                    mfaToken = mfaToken,
                    onSuccess = { authenticatorsList ->
                        // Get first active SMS authenticator
                        val smsAuth = authenticatorsList.firstActiveSmsAuthenticator
                        if (smsAuth != null) {
                            // Step 3: Trigger SMS challenge
                            triggerSmsChallenge(
                                mfaToken = mfaToken,
                                authenticatorId = smsAuth.id,
                                onSuccess = { challenge ->
                                    // Step 4: Verify OTP code
                                    val oobCode = challenge.oobCode
                                    if (oobCode != null) {
                                        verifySmsOtp(
                                            mfaToken = mfaToken,
                                            oobCode = oobCode,
                                            bindingCode = otpCode,
                                            onSuccess = onSuccess,
                                            onError = onError
                                        )
                                    } else {
                                        onError(AuthenticationException("oob_code not found in challenge response"))
                                    }
                                },
                                onError = onError
                            )
                        } else {
                            onError(AuthenticationException("No active SMS authenticator found"))
                        }
                    },
                    onError = onError
                )
            },
            onSuccess = onSuccess,
            onError = onError
        )
    }
}

/**
 * Coroutines-based implementation for modern Android apps
 */
class SmsOtpMfaFlowCoroutines {

    private lateinit var auth0: Auth0
    private lateinit var authClient: AuthenticationAPIClient

    fun initialize(clientId: String, domain: String) {
        auth0 = Auth0.getInstance(clientId, domain)
        authClient = AuthenticationAPIClient(auth0)
    }

    /**
     * Complete SMS OTP MFA flow using Kotlin Coroutines
     * This provides a cleaner, sequential implementation
     */
    suspend fun completeSmsOtpMfaFlow(
        username: String,
        password: String,
        realm: String,
        otpCode: String
    ): Credentials {
        try {
            // Step 1: Attempt initial login
            return try {
                authClient.login(username, password, realm)
                    .validateClaims()
                    .await()
            } catch (error: AuthenticationException) {
                if (!error.isMultifactorRequired) {
                    throw error
                }

                // Step 2: Extract MFA token
                val mfaToken = error.mfaToken
                    ?: throw AuthenticationException("mfa_token not found in error response")

                // Step 3: List authenticators
                val authenticatorsList = authClient.listAuthenticators(mfaToken).await()

                // Step 4: Get SMS authenticator
                val smsAuth = authenticatorsList.firstActiveSmsAuthenticator
                    ?: throw AuthenticationException("No active SMS authenticator found")

                // Step 5: Trigger SMS challenge
                val challenge = authClient.multifactorChallenge(
                    mfaToken = mfaToken,
                    challengeType = "oob",
                    authenticatorId = smsAuth.id
                ).await()

                // Step 6: Verify OTP code
                val oobCode = challenge.oobCode
                    ?: throw AuthenticationException("oob_code not found in challenge response")

                authClient.loginWithOOB(
                    mfaToken = mfaToken,
                    oobCode = oobCode,
                    bindingCode = otpCode
                )
                    .validateClaims()
                    .await()
            }
        } catch (e: Exception) {
            throw AuthenticationException("SMS OTP MFA flow failed", e)
        }
    }
}
