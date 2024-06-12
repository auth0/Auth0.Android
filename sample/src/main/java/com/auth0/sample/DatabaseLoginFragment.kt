package com.auth0.sample

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.storage.AuthenticationLevel
import com.auth0.android.authentication.storage.CredentialsManagerException
import com.auth0.android.authentication.storage.LocalAuthenticationOptions
import com.auth0.android.authentication.storage.SecureCredentialsManager
import com.auth0.android.authentication.storage.SharedPreferencesStorage
import com.auth0.android.callback.Callback
import com.auth0.android.management.ManagementException
import com.auth0.android.management.UsersAPIClient
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.request.DefaultClient
import com.auth0.android.result.Credentials
import com.auth0.android.result.UserProfile
import com.auth0.sample.databinding.FragmentDatabaseLoginBinding
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class DatabaseLoginFragment : Fragment() {

    private val scope = "openid profile email read:current_user update:current_user_metadata"

    private val account: Auth0 by lazy {
        // -- REPLACE this credentials with your own Auth0 app credentials!
        val account = Auth0(
            getString(R.string.com_auth0_client_id),
            getString(R.string.com_auth0_domain)
        )
        // Only enable network traffic logging on production environments!
        account.networkingClient = DefaultClient(enableLogging = true)
        account
    }

    private val audience: String by lazy {
        "https://${getString(R.string.com_auth0_domain)}/api/v2/"
    }

    private val authenticationApiClient: AuthenticationAPIClient by lazy {
        AuthenticationAPIClient(account)
    }

    private val credentialsManager: SecureCredentialsManager by lazy {
        val storage = SharedPreferencesStorage(requireContext())
        val manager = SecureCredentialsManager(requireContext(), authenticationApiClient, storage)
        manager
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val binding = FragmentDatabaseLoginBinding.inflate(inflater, container, false)
        binding.btLogin.setOnClickListener {
            val email = binding.textEmail.text.toString()
            val password = binding.textPassword.text.toString()
            dbLogin(email, password)
        }
        binding.btLoginAsync.setOnClickListener {
            launchAsync {
                val email = binding.textEmail.text.toString()
                val password = binding.textPassword.text.toString()
                dbLoginAsync(email, password)
            }
        }
        binding.btWebAuth.setOnClickListener {
            webAuth()
        }
        binding.btWebAuthAsync.setOnClickListener {
            launchAsync {
                webAuthAsync()
            }
        }
        binding.btWebLogout.setOnClickListener {
            webLogout()
        }
        binding.btWebLogoutAsync.setOnClickListener {
            launchAsync {
                webLogoutAsync()
            }
        }
        binding.btDeleteCredentials.setOnClickListener {
            deleteCreds()
        }
        binding.btGetCredentials.setOnClickListener {
            getCreds()
        }
        binding.btGetCredentialsAsync.setOnClickListener {
            launchAsync {
                getCredsAsync()
            }
        }
        binding.btGetProfile.setOnClickListener {
            getProfile()
        }
        binding.btGetProfileAsync.setOnClickListener {
            launchAsync {
                getProfileAsync()
            }
        }
        binding.btUpdateMeta.setOnClickListener {
            updateMeta()
        }
        binding.btUpdateMetaAsync.setOnClickListener {
            launchAsync {
                updateMetaAsync()
            }
        }
        return binding.root
    }

    private suspend fun dbLoginAsync(email: String, password: String) {
        try {
            val result =
                authenticationApiClient.login(email, password, "Username-Password-Authentication")
                    .validateClaims()
                    .addParameter("scope", scope)
                    .addParameter("audience", audience)
                    .await()
            credentialsManager.saveCredentials(result)
            Snackbar.make(
                requireView(),
                "Hello ${result.user.name}",
                Snackbar.LENGTH_LONG
            ).show()
        } catch (error: AuthenticationException) {
            Snackbar.make(requireView(), error.getDescription(), Snackbar.LENGTH_LONG)
                .show()
        }
    }

    private fun dbLogin(email: String, password: String) {
        authenticationApiClient.login(email, password, "Username-Password-Authentication")
            .validateClaims()
            .addParameter("scope", scope)
            .addParameter("audience", audience)
            //Additional customization to the request goes here
            .start(object : Callback<Credentials, AuthenticationException> {
                override fun onFailure(error: AuthenticationException) {
                    Snackbar.make(requireView(), error.getDescription(), Snackbar.LENGTH_LONG)
                        .show()
                }

                override fun onSuccess(result: Credentials) {
                    credentialsManager.saveCredentials(result)
                    Snackbar.make(
                        requireView(),
                        "Hello ${result.user.name}",
                        Snackbar.LENGTH_LONG
                    ).show()
                }
            })
    }

    private fun webAuth() {
        WebAuthProvider.login(account)
            .withScheme(getString(R.string.com_auth0_scheme))
            .withAudience(audience)
            .withScope(scope)
            .start(requireContext(), object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    credentialsManager.saveCredentials(result)
                    Snackbar.make(
                        requireView(),
                        "Hello ${result.user.name}",
                        Snackbar.LENGTH_LONG
                    ).show()
                }

                override fun onFailure(error: AuthenticationException) {
                    val message =
                        if (error.isCanceled) "Browser was closed" else error.getDescription()
                    Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
                }
            })
    }

    private suspend fun webAuthAsync() {
        try {
            val credentials = WebAuthProvider.login(account)
                .withScheme(getString(R.string.com_auth0_scheme))
                .withAudience(audience)
                .withScope(scope)
                .await(requireContext())
            credentialsManager.saveCredentials(credentials)
            Snackbar.make(
                requireView(),
                "Hello ${credentials.user.name}",
                Snackbar.LENGTH_LONG
            ).show()
        } catch (error: AuthenticationException) {
            val message =
                if (error.isCanceled) "Browser was closed" else error.getDescription()
            Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
        }
    }

    private fun webLogout() {
        WebAuthProvider.logout(account)
            .withScheme(getString(R.string.com_auth0_scheme))
            .start(requireContext(), object : Callback<Void?, AuthenticationException> {
                override fun onSuccess(result: Void?) {
                    Snackbar.make(
                        requireView(),
                        "Logged out",
                        Snackbar.LENGTH_LONG
                    ).show()
                }

                override fun onFailure(error: AuthenticationException) {
                    val message =
                        if (error.isCanceled) "Browser was closed" else error.getDescription()
                    Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
                }

            })
    }

    private suspend fun webLogoutAsync() {
        try {
            WebAuthProvider.logout(account)
                .withScheme(getString(R.string.com_auth0_scheme))
                .await(requireContext())
            Snackbar.make(
                requireView(),
                "Logged out",
                Snackbar.LENGTH_LONG
            ).show()
        } catch (error: AuthenticationException) {
            val message =
                if (error.isCanceled) "Browser was closed" else error.getDescription()
            Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
        }
    }

    private fun deleteCreds() {
        credentialsManager.clearCredentials()
    }

    private fun getCreds() {
        val localAuthenticationOptions =
            LocalAuthenticationOptions.Builder().title("Biometric").description("description")
                .authenticator(AuthenticationLevel.STRONG).negativeButtonText("Cancel")
                .build()
        credentialsManager.getCredentialsWithAuthentication(
            requireActivity(),
            localAuthenticationOptions,
            null,
            300,
            emptyMap(),
            emptyMap(),
            false,
            object : Callback<Credentials, CredentialsManagerException> {
                override fun onSuccess(result: Credentials) {
                    Snackbar.make(
                        requireView(),
                        "Got credentials - ${result.accessToken}",
                        Snackbar.LENGTH_LONG
                    ).show()
                }

                override fun onFailure(error: CredentialsManagerException) {
                    Snackbar.make(requireView(), "${error.message}", Snackbar.LENGTH_LONG).show()

                    when (error) {
                        CredentialsManagerException.NO_CREDENTIALS -> {
                            // handle no credentials scenario
                            println("NO_CREDENTIALS: $error")
                        }
                        CredentialsManagerException.NO_REFRESH_TOKEN -> {
                            // handle no refresh token scenario
                            println("NO_REFRESH_TOKEN: $error")
                        }
                        CredentialsManagerException.STORE_FAILED -> {
                            // handle store failed scenario
                            println("STORE_FAILED: $error")
                        }
                        // ... similarly for other error codes
                    }
                }
            })
    }

    private suspend fun getCredsAsync() {
        try {
            val credentials = credentialsManager.awaitCredentials()
            Snackbar.make(
                requireView(),
                "Got credentials - ${credentials.accessToken}",
                Snackbar.LENGTH_LONG
            ).show()
        } catch (error: CredentialsManagerException) {
            Snackbar.make(requireView(), "${error.message}", Snackbar.LENGTH_LONG).show()
        }
    }

    private fun getProfile() {
        credentialsManager.getCredentials(object :
            Callback<Credentials, CredentialsManagerException> {
            override fun onSuccess(result: Credentials) {
                val users = UsersAPIClient(account, result.accessToken)
                users.getProfile(result.user.getId()!!)
                    .start(object : Callback<UserProfile, ManagementException> {
                        override fun onFailure(error: ManagementException) {
                            Snackbar.make(
                                requireView(),
                                error.getDescription(),
                                Snackbar.LENGTH_LONG
                            ).show()
                        }

                        override fun onSuccess(result: UserProfile) {
                            Snackbar.make(
                                requireView(),
                                "Got profile for ${result.name}",
                                Snackbar.LENGTH_LONG
                            ).show()
                        }
                    })
            }

            override fun onFailure(error: CredentialsManagerException) {
                Snackbar.make(requireView(), "${error.message}", Snackbar.LENGTH_LONG).show()
            }
        })
    }

    private suspend fun getProfileAsync() {
        try {
            val credentials = credentialsManager.awaitCredentials()
            val users = UsersAPIClient(account, credentials.accessToken)
            val user = users.getProfile(credentials.user.getId()!!).await()
            Snackbar.make(
                requireView(),
                "Got profile for ${user.name}",
                Snackbar.LENGTH_LONG
            ).show()
        } catch (error: CredentialsManagerException) {
            Snackbar.make(requireView(), "${error.message}", Snackbar.LENGTH_LONG).show()
        } catch (error: ManagementException) {
            Snackbar.make(requireView(), error.getDescription(), Snackbar.LENGTH_LONG).show()
        }
    }

    private fun updateMeta() {
        val metadata = mapOf(
            "random" to (0..100).random(),
        )

        credentialsManager.getCredentials(object :
            Callback<Credentials, CredentialsManagerException> {
            override fun onSuccess(result: Credentials) {
                val users = UsersAPIClient(account, result.accessToken)
                users.updateMetadata(result.user.getId()!!, metadata)
                    .start(object : Callback<UserProfile, ManagementException> {
                        override fun onFailure(error: ManagementException) {
                            Snackbar.make(
                                requireView(),
                                error.getDescription(),
                                Snackbar.LENGTH_LONG
                            ).show()
                        }

                        override fun onSuccess(result: UserProfile) {
                            Snackbar.make(
                                requireView(),
                                "Updated metadata for ${result.name} to ${result.getUserMetadata()}",
                                Snackbar.LENGTH_LONG
                            ).show()
                        }
                    })
            }

            override fun onFailure(error: CredentialsManagerException) {
                Snackbar.make(requireView(), "${error.message}", Snackbar.LENGTH_LONG).show()
            }
        })
    }

    private suspend fun updateMetaAsync() {
        val metadata = mapOf(
            "random" to (0..100).random(),
        )

        try {
            val credentials = credentialsManager.awaitCredentials()
            val users = UsersAPIClient(account, credentials.accessToken)
            val user = users.updateMetadata(credentials.user.getId()!!, metadata).await()
            Snackbar.make(
                requireView(),
                "Updated metadata for ${user.name} to ${user.getUserMetadata()}",
                Snackbar.LENGTH_LONG
            ).show()
        } catch (error: CredentialsManagerException) {
            Snackbar.make(requireView(), "${error.message}", Snackbar.LENGTH_LONG).show()
        } catch (error: ManagementException) {
            Snackbar.make(requireView(), error.getDescription(), Snackbar.LENGTH_LONG).show()
        }
    }

    private fun launchAsync(runnable: suspend () -> Unit) {
        //Use a better scope like lifecycleScope or viewModelScope
        GlobalScope.launch(Dispatchers.Main) {
            runnable.invoke()
        }
    }
}