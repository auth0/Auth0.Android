package com.auth0.sample

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.result.AuthenticatorsList
import com.auth0.android.result.Challenge
import com.auth0.android.result.Credentials
import kotlinx.coroutines.launch

/**
 * SMS OTP MFA Fragment - POC Implementation
 *
 * This fragment demonstrates the complete SMS OTP MFA flow with UI:
 * 1. Username/Password login form
 * 2. SMS OTP input form (shown when MFA is required)
 * 3. Success/Error handling
 *
 * Flow States:
 * - STATE_LOGIN: Initial login form
 * - STATE_MFA_REQUIRED: Show OTP input after MFA is required
 * - STATE_SUCCESS: Authentication completed
 */
class SmsOtpMfaFragment : Fragment() {

    companion object {
        private const val TAG = "SmsOtpMfaFragment"
    }

    private lateinit var auth0: Auth0
    private lateinit var authClient: AuthenticationAPIClient

    // UI Components
    private lateinit var loginForm: ViewGroup
    private lateinit var mfaForm: ViewGroup
    private lateinit var successView: ViewGroup
    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var otpInput: EditText
    private lateinit var loginButton: Button
    private lateinit var verifyOtpButton: Button
    private lateinit var resendOtpButton: Button
    private lateinit var logoutButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var userInfoText: TextView

    // MFA State
    private var mfaToken: String? = null
    private var oobCode: String? = null

    enum class FlowState {
        LOGIN,
        MFA_REQUIRED,
        SUCCESS
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize Auth0
        auth0 = Auth0.getInstance(
            getString(R.string.com_auth0_client_id),
            getString(R.string.com_auth0_domain)
        )
        authClient = AuthenticationAPIClient(auth0)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_sms_otp_mfa, container, false)
        
        // Initialize UI components
        loginForm = view.findViewById(R.id.loginForm)
        mfaForm = view.findViewById(R.id.mfaForm)
        successView = view.findViewById(R.id.successView)
        usernameInput = view.findViewById(R.id.usernameInput)
        passwordInput = view.findViewById(R.id.passwordInput)
        otpInput = view.findViewById(R.id.otpInput)
        loginButton = view.findViewById(R.id.loginButton)
        verifyOtpButton = view.findViewById(R.id.verifyOtpButton)
        resendOtpButton = view.findViewById(R.id.resendOtpButton)
        logoutButton = view.findViewById(R.id.logoutButton)
        progressBar = view.findViewById(R.id.progressBar)
        statusText = view.findViewById(R.id.statusText)
        userInfoText = view.findViewById(R.id.userInfoText)
        
        return view
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupListeners()
        setState(FlowState.LOGIN)
    }

    private fun setupListeners() {
        loginButton.setOnClickListener {
            val username = usernameInput.text.toString()
            val password = passwordInput.text.toString()
            val realm = "Username-Password-Authentication" // Default realm

            if (username.isEmpty() || password.isEmpty()) {
                showError("Please enter username and password")
                return@setOnClickListener
            }

            performLogin(username, password, realm)
        }

        verifyOtpButton.setOnClickListener {
            val otpCode = otpInput.text.toString()

            if (otpCode.isEmpty()) {
                showError("Please enter the OTP code")
                return@setOnClickListener
            }

            verifyOtp(otpCode)
        }

        resendOtpButton.setOnClickListener {
            // Re-trigger SMS challenge
            val error = AuthenticationException("mfa_required", "MFA Required")
            handleMfaRequired(error)
        }

        logoutButton.setOnClickListener {
            // Clear state and go back to login
            mfaToken = null
            oobCode = null
            usernameInput.text?.clear()
            passwordInput.text?.clear()
            otpInput.text?.clear()
            setState(FlowState.LOGIN)
        }
    }

    /**
     * Step 1: Perform initial login
     */
    private fun performLogin(username: String, password: String, realm: String) {
        showLoading(true)
        statusText.text = "Authenticating..."

        authClient.login(username, password, realm)
            .validateClaims()
            .start(object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    showLoading(false)
                    handleLoginSuccess(result)
                }

                override fun onFailure(error: AuthenticationException) {
                    showLoading(false)
                    if (error.isMultifactorRequired) {
                        handleMfaRequired(error)
                    } else {
                        showError("Login failed: ${error.getDescription()}")
                    }
                }
            })
    }

    /**
     * Step 2: Handle MFA required - trigger SMS challenge directly
     * Note: We skip listing authenticators and directly trigger the SMS challenge
     * because the /mfa/authenticators endpoint is not available in Auth0 Authentication API
     */
    private fun handleMfaRequired(error: AuthenticationException) {
        // Debug logging
        android.util.Log.d(TAG, "=== MFA Required Debug ===")
        android.util.Log.d(TAG, "Error code: ${error.getCode()}")
        android.util.Log.d(TAG, "Error description: ${error.getDescription()}")
        android.util.Log.d(TAG, "isMultifactorRequired: ${error.isMultifactorRequired}")
        android.util.Log.d(TAG, "Trying to get mfa_token...")
        
        val token = error.mfaToken
        android.util.Log.d(TAG, "mfaToken result: ${if (token == null) "NULL" else "Found (length: ${token.length})"}")
        
        if (token == null) {
            showError("MFA token not found in response")
            return
        }

        mfaToken = token
        android.util.Log.d(TAG, "Stored mfaToken successfully")
        statusText.text = "Sending SMS OTP to your phone..."

        // Directly trigger SMS challenge (skip listing authenticators)
        // Auth0 will use the user's enrolled SMS authenticator automatically
        triggerSmsChallenge(token)
    }

    /**
     * Step 3: Trigger SMS challenge directly
     * Note: We pass authenticatorId as null, Auth0 will use the user's enrolled SMS authenticator
     */
    private fun triggerSmsChallenge(token: String) {
        android.util.Log.d(TAG, "Triggering SMS challenge...")
        
        authClient.multifactorChallenge(
            mfaToken = token,
            challengeType = "oob",
            authenticatorId = null  // Auth0 will use the enrolled SMS authenticator
        ).start(object : Callback<Challenge, AuthenticationException> {
            override fun onSuccess(result: Challenge) {
                android.util.Log.d(TAG, "SMS challenge successful!")
                oobCode = result.oobCode
                android.util.Log.d(TAG, "OOB Code: ${oobCode?.take(10)}...")
                setState(FlowState.MFA_REQUIRED)
                statusText.text = "SMS sent! Enter the code below."
            }

            override fun onFailure(error: AuthenticationException) {
                android.util.Log.e(TAG, "SMS challenge failed: ${error.getDescription()}")
                showError("Failed to send SMS: ${error.getDescription()}")
            }
        })
    }

    /**
     * Step 4: Verify OTP code
     */
    private fun verifyOtp(otpCode: String) {
        val token = mfaToken
        val code = oobCode

        if (token == null || code == null) {
            showError("Invalid state - missing MFA token or OOB code")
            return
        }

        showLoading(true)
        statusText.text = "Verifying OTP..."

        authClient.loginWithOOB(
            mfaToken = token,
            oobCode = code,
            bindingCode = otpCode
        )
            .validateClaims()
            .start(object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    showLoading(false)
                    handleLoginSuccess(result)
                }

                override fun onFailure(error: AuthenticationException) {
                    showLoading(false)
                    if (error.isMultifactorCodeInvalid) {
                        showError("Invalid or expired OTP code. Please try again.")
                    } else {
                        showError("Verification failed: ${error.getDescription()}")
                    }
                }
            })
    }

    /**
     * Update UI state
     */
    private fun setState(state: FlowState) {
        when (state) {
            FlowState.LOGIN -> {
                loginForm.visibility = View.VISIBLE
                mfaForm.visibility = View.GONE
                successView.visibility = View.GONE
                statusText.text = "Enter your credentials to login"
            }
            FlowState.MFA_REQUIRED -> {
                loginForm.visibility = View.GONE
                mfaForm.visibility = View.VISIBLE
                successView.visibility = View.GONE
            }
            FlowState.SUCCESS -> {
                loginForm.visibility = View.GONE
                mfaForm.visibility = View.GONE
                successView.visibility = View.VISIBLE
            }
        }
    }

    private fun showLoading(show: Boolean) {
        progressBar.visibility = if (show) View.VISIBLE else View.GONE
        loginButton.isEnabled = !show
        verifyOtpButton.isEnabled = !show
    }

    private fun showError(message: String) {
        Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show()
        statusText.text = message
    }

    private fun handleLoginSuccess(credentials: Credentials) {
        setState(FlowState.SUCCESS)
        userInfoText.text = "Welcome!\n\n" +
                "Email: ${credentials.user.email ?: "N/A"}\n" +
                "User ID: ${credentials.user.getId()}\n\n" +
                "Access Token: ${credentials.accessToken.take(20)}..."
        statusText.text = "Authentication successful!"
    }
}

// Coroutines-based Fragment implementation - TODO: Complete implementation


