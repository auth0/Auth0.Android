package com.auth0.sample

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialException
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.PasswordlessType as PasswordlessDelivery
import com.auth0.android.authentication.passwordless.DeliveryMethod
import com.auth0.android.callback.Callback
import com.auth0.android.embedded.DiscoveryResult
import com.auth0.android.embedded.EmbeddedAuthClient
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.embedded.LoginOption
import com.auth0.android.embedded.GrantType
import com.auth0.android.embedded.PasswordlessIdentifier
import com.auth0.android.embedded.PasswordlessType
import com.auth0.android.request.DefaultClient
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.result.Credentials
import com.auth0.android.result.PasswordlessChallenge
import com.auth0.sample.databinding.FragmentEmbeddedLoginBinding
import com.google.android.material.snackbar.Snackbar
import com.google.gson.Gson
import kotlinx.coroutines.launch

/**
 * Composes a login screen from `GET /e/discovery` instead of from assumptions made at build time.
 */
class EmbeddedLoginFragment : Fragment() {

    private val account: Auth0 by lazy {
        // -- REPLACE this credentials with your own Auth0 app credentials!
        val account = Auth0.getInstance(
            getString(R.string.com_auth0_client_id),
            getString(R.string.com_auth0_domain)
        )
        // Only enable network traffic logging on production environments!
        account.networkingClient = DefaultClient.Builder()
            .enableLogging(true)
            .build()
        account
    }

    private val embeddedAuthClient: EmbeddedAuthClient by lazy { EmbeddedAuthClient(account) }

    private val authenticationApiClient: AuthenticationAPIClient by lazy {
        AuthenticationAPIClient(account)
    }

    private val credentialManager: CredentialManager by lazy {
        CredentialManager.create(requireContext())
    }

    private lateinit var binding: FragmentEmbeddedLoginBinding

    private var pendingOtp: PendingOtp? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        binding = FragmentEmbeddedLoginBinding.inflate(inflater, container, false)

        binding.btDiscover.setOnClickListener { discover() }
        binding.btDiscoverAsync.setOnClickListener { launchAsync { discoverAsync() } }
        binding.btOtpVerify.setOnClickListener {
            val pending = pendingOtp ?: return@setOnClickListener
            launchAsync { verifyOtp(pending, binding.textOtpCode.text.toString()) }
        }

        return binding.root
    }

    private fun discover() {
        embeddedAuthClient.discover()
            .start(object : Callback<DiscoveryResult, EmbeddedAuthException> {
                override fun onSuccess(result: DiscoveryResult) {
                    render(result)
                }

                override fun onFailure(error: EmbeddedAuthException) {
                    showDiscoveryFailure(error)
                }
            })
    }

    private suspend fun discoverAsync() {
        try {
            render(embeddedAuthClient.discover().await())
        } catch (error: EmbeddedAuthException) {
            showDiscoveryFailure(error)
        }
    }

    private fun showDiscoveryFailure(error: EmbeddedAuthException) {
        binding.containerOptions.removeAllViews()
        hidePasswordForm()
        hideOtpForm()
        binding.textStatus.text = "Discovery failed: ${error.code} — ${error.description}"
        show(error.description)
    }

    /**
     * Server order is the default render order, so the options are walked as they arrived. Both
     * password types are checked: a tenant with no default directory advertises only
     * [GrantType.PASSWORD_REALM].
     */
    private fun render(result: DiscoveryResult) {
        binding.containerOptions.removeAllViews()
        hidePasswordForm()
        hideOtpForm()

        if (result.options.isEmpty()) {
            binding.textStatus.text = "This client has no login options enabled."
            return
        }

        binding.textStatus.text = buildString {
            append("${result.options.size} option(s): ")
            append(result.types.joinToString { it.name })
            val socials = result.options.filterIsInstance<LoginOption.NativeSocial>()
            if (socials.isNotEmpty()) {
                append("\nSocial: ${socials.joinToString { it.subjectTokenType }}")
            }
            val password = GrantType.PASSWORD in result.types
            val passwordRealm = GrantType.PASSWORD_REALM in result.types
            if (password || passwordRealm) {
                append("\nPassword login is available.")
            }
        }

        result.options.forEach { option -> addEntryPoints(option) }
    }

    /**
     * Adds a button per entry point the option provides, which can be more than one.
     */
    private fun addEntryPoints(option: LoginOption) {
        when (option) {
            is LoginOption.Password -> addButton("Log in with a password") {
                showPasswordForm(realm = null)
            }

            is LoginOption.PasswordRealm -> addButton("Log in with a password (${option.realm})") {
                showPasswordForm(realm = option.realm)
            }

            is LoginOption.Passkey -> addButton("Log in with a passkey") {
                launchAsync { passkeyLogin(option) }
            }

            // Two identifiers means two ways to sign in, so one button each.
            is LoginOption.PasswordlessOtp -> option.identifiers.forEach { identifier ->
                val label = when (identifier) {
                    PasswordlessIdentifier.EMAIL -> "Email me a code (${option.connection})"
                    PasswordlessIdentifier.PHONE_NUMBER -> "Text me a code (${option.connection})"
                }
                addButton(label) { showOtpForm(option, identifier) }
            }

            is LoginOption.NativeSocial -> addButton("Continue with a social provider") {
                show("Get a ${option.subjectTokenType} token from the provider's SDK, then call loginWithNativeSocialToken.")
            }

            is LoginOption.EmbeddedAuthorize -> addButton("Continue (${option.connection})") {
                show("Embedded authorize is not implemented in this sample yet.")
            }

            is LoginOption.Unknown -> addButton("Unsupported: ${option.rawGrantType}") {
                show("This SDK version does not model ${option.rawGrantType}. Upgrade to use it.")
            }
        }
    }

    private fun addButton(label: String, onClick: () -> Unit) {
        val button = Button(requireContext()).apply {
            text = label
            textSize = 12f
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setOnClickListener { onClick() }
        }
        binding.containerOptions.addView(button)
    }

    private fun showPasswordForm(realm: String?) {
        hideOtpForm()
        binding.textPasswordHeader.text =
            if (realm == null) "Log in with a password" else "Log in with a password ($realm)"
        binding.groupPassword.visibility = View.VISIBLE
        binding.btPasswordLogin.setOnClickListener {
            launchAsync {
                passwordLogin(
                    email = binding.textEmail.text.toString(),
                    password = binding.textPassword.text.toString(),
                    realm = realm
                )
            }
        }
    }

    private fun hidePasswordForm() {
        binding.groupPassword.visibility = View.GONE
    }

    private suspend fun passwordLogin(email: String, password: String, realm: String?) {
        try {
            val credentials = if (realm == null) {
                authenticationApiClient.login(email, password)
            } else {
                authenticationApiClient.login(email, password, realm)
            }.validateClaims().await()
            showCredentials(credentials)
        } catch (error: AuthenticationException) {
            show(error.getDescription())
        }
    }

    private suspend fun passkeyLogin(option: LoginOption.Passkey) {
        try {
            val challenge = authenticationApiClient
                .passkeyChallenge(realm = option.connection)
                .await()
            val request = GetCredentialRequest(
                listOf(GetPublicKeyCredentialOption(Gson().toJson(challenge.authParamsPublicKey)))
            )
            val credential = credentialManager.getCredential(requireContext(), request).credential
            if (credential !is PublicKeyCredential) {
                show("The credential manager returned something other than a passkey.")
                return
            }
            val authResponse = Gson().fromJson(
                credential.authenticationResponseJson,
                PublicKeyCredentials::class.java
            )
            val credentials = authenticationApiClient
                .signinWithPasskey(challenge.authSession, authResponse, option.connection)
                .validateClaims()
                .await()
            showCredentials(credentials)
        } catch (error: GetCredentialException) {
            show(error.errorMessage?.toString() ?: "Could not get a passkey.")
        } catch (error: AuthenticationException) {
            show(error.getDescription())
        }
    }

    private fun showOtpForm(option: LoginOption.PasswordlessOtp, identifier: PasswordlessIdentifier) {
        hidePasswordForm()
        hideOtpForm()
        binding.textOtpHeader.text = "Log in with a one-time code (${option.connection})"
        binding.textOtpIdentifier.hint = when (identifier) {
            PasswordlessIdentifier.EMAIL -> "Email"
            PasswordlessIdentifier.PHONE_NUMBER -> "Phone number"
        }
        binding.groupOtpIdentifier.visibility = View.VISIBLE
        binding.btOtpSend.setOnClickListener {
            launchAsync {
                sendOtp(option, identifier, binding.textOtpIdentifier.text.toString())
            }
        }
    }

    private fun hideOtpForm() {
        binding.groupOtpIdentifier.visibility = View.GONE
        binding.groupOtpCode.visibility = View.GONE
        pendingOtp = null
    }

    /**
     * The variant decides which challenge to issue, and the two are not interchangeable: legacy
     * verifies with the identifier, while the database flow verifies with the `auth_session` it
     * returns here.
     */
    private suspend fun sendOtp(
        option: LoginOption.PasswordlessOtp,
        identifier: PasswordlessIdentifier,
        value: String
    ) {
        try {
            pendingOtp = when (option.type) {
                PasswordlessType.LEGACY -> {
                    when (identifier) {
                        // The default is a magic link, so a code has to be asked for.
                        PasswordlessIdentifier.EMAIL -> authenticationApiClient
                            .passwordlessWithEmail(value, PasswordlessDelivery.CODE, option.connection)

                        PasswordlessIdentifier.PHONE_NUMBER -> authenticationApiClient
                            .passwordlessWithSMS(value, PasswordlessDelivery.CODE, option.connection)
                    }.await()
                    PendingOtp.Legacy(option.connection, identifier, value)
                }

                PasswordlessType.AUTH0 -> {
                    val passwordless = authenticationApiClient.passwordlessClient()
                    val challenge = when (identifier) {
                        PasswordlessIdentifier.EMAIL ->
                            passwordless.challengeWithEmail(value, option.connection)

                        PasswordlessIdentifier.PHONE_NUMBER -> passwordless
                            .challengeWithPhoneNumber(value, option.connection, DeliveryMethod.TEXT)
                    }.await()
                    PendingOtp.Database(challenge)
                }
            }
            binding.groupOtpCode.visibility = View.VISIBLE
            show("Code sent to $value.")
        } catch (error: AuthenticationException) {
            show(error.getDescription())
        }
    }

    private suspend fun verifyOtp(pending: PendingOtp, code: String) {
        try {
            val credentials = when (pending) {
                is PendingOtp.Legacy -> when (pending.identifier) {
                    PasswordlessIdentifier.EMAIL -> authenticationApiClient
                        .loginWithEmail(pending.value, code, pending.connection)

                    PasswordlessIdentifier.PHONE_NUMBER -> authenticationApiClient
                        .loginWithPhoneNumber(pending.value, code, pending.connection)
                }

                is PendingOtp.Database -> authenticationApiClient
                    .passwordlessClient()
                    .loginWithOTP(pending.challenge, code)
            }.validateClaims().await()
            showCredentials(credentials)
        } catch (error: AuthenticationException) {
            show(error.getDescription())
        }
    }

    /** What the second leg of the flow needs, which differs by variant. */
    private sealed class PendingOtp {
        data class Legacy(
            val connection: String,
            val identifier: PasswordlessIdentifier,
            val value: String
        ) : PendingOtp()

        data class Database(val challenge: PasswordlessChallenge) : PendingOtp()
    }

    private fun showCredentials(credentials: Credentials) {
        show("Hello ${credentials.user.name}")
    }

    private fun show(message: String) {
        Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
    }

    private fun launchAsync(runnable: suspend () -> Unit) {
        viewLifecycleOwner.lifecycleScope.launch { runnable.invoke() }
    }
}
