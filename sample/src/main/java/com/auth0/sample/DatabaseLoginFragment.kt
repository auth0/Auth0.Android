package com.auth0.sample

import android.os.Bundle
import android.os.CancellationSignal
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.fragment.app.Fragment
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.storage.AuthenticationLevel
import com.auth0.android.authentication.storage.CredentialsManager
import com.auth0.android.authentication.storage.CredentialsManagerException
import com.auth0.android.authentication.storage.LocalAuthenticationOptions
import com.auth0.android.authentication.storage.SecureCredentialsManager
import com.auth0.android.authentication.storage.SharedPreferencesStorage
import com.auth0.android.callback.Callback
import com.auth0.android.dpop.DPoPProvider
import com.auth0.android.management.ManagementException
import com.auth0.android.management.UsersAPIClient
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.request.DefaultClient
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.request.UserData
import com.auth0.android.result.Credentials
import com.auth0.android.result.PasskeyChallenge
import com.auth0.android.result.PasskeyRegistrationChallenge
import com.auth0.android.result.UserProfile
import com.auth0.sample.databinding.FragmentDatabaseLoginBinding
import com.google.android.material.snackbar.Snackbar
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.util.concurrent.Executors

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class DatabaseLoginFragment : Fragment() {

    private val scope = "openid profile email read:current_user update:current_user_metadata"

    private val account: Auth0 by lazy {
        // -- REPLACE this credentials with your own Auth0 app credentials!
        val account = Auth0.getInstance(
            getString(R.string.com_auth0_client_id),
            getString(R.string.com_auth0_domain)
        )
        // Only enable network traffic logging on production environments!
        account.networkingClient = DefaultClient(enableLogging = true)
        account
    }

    private val audience: String by lazy {
        "https://firstresourceserver/"
//        "https://${getString(R.string.com_auth0_domain)}/api/v2/"
    }

    private val credentialManager: CredentialManager by lazy {
        CredentialManager.create(requireContext())
    }

    private val authenticationApiClient: AuthenticationAPIClient by lazy {
        AuthenticationAPIClient(account)
    }

    private val secureCredentialsManager: SecureCredentialsManager by lazy {
        val storage = SharedPreferencesStorage(requireContext())
        val manager = SecureCredentialsManager(
            requireContext(),
            account,
            storage,
            requireActivity(),
            localAuthenticationOptions
        )
        manager
    }

    private val credentialsManager: CredentialsManager by lazy {
        val storage = SharedPreferencesStorage(requireContext())
        val manager = CredentialsManager(authenticationApiClient, storage)
        manager
    }

    private val localAuthenticationOptions =
        LocalAuthenticationOptions.Builder()
            .setTitle("Biometric")
            .setDescription("description")
            .setAuthenticationLevel(AuthenticationLevel.STRONG)
            .setNegativeButtonText("Cancel")
            .setDeviceCredentialFallback(true)
            .build()

    private val callback = object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
            credentialsManager.saveCredentials(result)
            Snackbar.make(
                requireView(),
                "Hello ${result.user.name}",
                Snackbar.LENGTH_LONG
            ).show()
        }

        override fun onFailure(error: AuthenticationException) {
            Snackbar.make(requireView(), error.getDescription(), Snackbar.LENGTH_LONG)
                .show()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
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

        binding.btSignupPasskey.setOnClickListener {
            passkeySignup(binding.textEmail.text.toString())
        }

        binding.btSignInPasskey.setOnClickListener {
            passkeySignin()
        }

        binding.btSignupPasskeyAsync.setOnClickListener {
            launchAsync {
                passkeySignupAsync(binding.textEmail.text.toString())
            }
        }

        binding.btSigninPasskeyAsync.setOnClickListener {
            launchAsync {
                passkeySigninAsync()
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
        binding.getCredentialsSecure.setOnClickListener {
            getCredsSecure()
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

    override fun onStart() {
        super.onStart()
        WebAuthProvider.addCallback(callback)
    }

    override fun onStop() {
        super.onStop()
        WebAuthProvider.removeCallback(callback)
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
            )
                .show()
        } catch (error: AuthenticationException) {
            Snackbar.make(requireView(), error.getDescription(), Snackbar.LENGTH_LONG).show()
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
        WebAuthProvider
            .enableDPoP(requireContext())
            .login(account)
            .withScheme(getString(R.string.com_auth0_scheme))
            .withAudience("https://firstresourceserver/")
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
                        if (error.isCanceled)
                            "Browser was closed"
                        else
                            error.getDescription()
                    Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG)
                        .show()
                }
            })
    }

    private suspend fun webAuthAsync() {
        try {
            val credentials =
                WebAuthProvider
                    .enableDPoP(requireContext())
                    .login(account)
                    .withScheme(getString(R.string.com_auth0_scheme))
                    .withAudience(audience)
                    .withScope(scope)
                    .await(requireContext())
            credentialsManager.saveCredentials(credentials)
            Snackbar.make(
                requireView(), "Hello ${credentials.user.name}", Snackbar.LENGTH_LONG
            ).show()
        } catch (error: AuthenticationException) {
            val message = if (error.isCanceled)
                "Browser was closed"
            else
                error.getDescription()
            Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
        }
    }

    private fun webLogout() {
        WebAuthProvider.logout(account)
            .withScheme(getString(R.string.com_auth0_scheme))
            .start(requireContext(), object : Callback<Void?, AuthenticationException> {
                override fun onSuccess(result: Void?) {
                    DPoPProvider.clearKeyPair()
                    Snackbar.make(
                        requireView(), "Logged out", Snackbar.LENGTH_LONG
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
                requireView(), "Logged out", Snackbar.LENGTH_LONG
            ).show()
        } catch (error: AuthenticationException) {
            val message = if (error.isCanceled) "Browser was closed" else error.getDescription()
            Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
        }
    }

    private fun deleteCreds() {
        credentialsManager.clearCredentials()
    }

    private fun getCreds() {
        credentialsManager.getCredentials(
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
                }
            })
    }

    private fun getCredsSecure() {
        secureCredentialsManager.getCredentials(object :
            Callback<Credentials, CredentialsManagerException> {
            override fun onSuccess(result: Credentials) {
                Snackbar.make(
                    requireView(), "Got credentials - ${result.accessToken}", Snackbar.LENGTH_LONG
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
                requireView(), "Got credentials - ${credentials.accessToken}", Snackbar.LENGTH_LONG
            ).show()
        } catch (error: CredentialsManagerException) {
            Snackbar.make(requireView(), "${error.message}", Snackbar.LENGTH_LONG).show()
        }
    }

    private fun getProfile() {
        credentialsManager.getCredentials(object :
            Callback<Credentials, CredentialsManagerException> {
            override fun onSuccess(result: Credentials) {
                val users = AuthenticationAPIClient(account)
                users.userInfo(result.accessToken, result.type)
                    .start(object : Callback<UserProfile, AuthenticationException> {
                        override fun onFailure(error: AuthenticationException) {

                            Snackbar.make(
                                requireView(), error.getDescription(), Snackbar.LENGTH_LONG
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
                requireView(), "Got profile for ${user.name}", Snackbar.LENGTH_LONG
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
                                requireView(), error.getDescription(), Snackbar.LENGTH_LONG
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

    private fun passkeySignup(email: String) {
        authenticationApiClient.signupWithPasskey(
            UserData(
                email = email
            )
        ).start(object : Callback<PasskeyRegistrationChallenge, AuthenticationException> {
            override fun onSuccess(result: PasskeyRegistrationChallenge) {
                val passKeyRegistrationChallenge = result
                val request = CreatePublicKeyCredentialRequest(
                    Gson().toJson(
                        passKeyRegistrationChallenge.authParamsPublicKey
                    )
                )
                var response: CreatePublicKeyCredentialResponse?

                credentialManager.createCredentialAsync(
                    requireContext(),
                    request,
                    CancellationSignal(),
                    Executors.newSingleThreadExecutor(),
                    object :
                        CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {

                        override fun onError(e: CreateCredentialException) {
                        }

                        override fun onResult(result: CreateCredentialResponse) {

                            response = result as CreatePublicKeyCredentialResponse
                            val authRequest = Gson().fromJson(
                                response?.registrationResponseJson,
                                PublicKeyCredentials::class.java
                            )

                            authenticationApiClient.signinWithPasskey(
                                passKeyRegistrationChallenge.authSession,
                                authRequest,
                                "Username-Password-Authentication"
                            )
                                .validateClaims()
                                .start(object : Callback<Credentials, AuthenticationException> {
                                    override fun onSuccess(result: Credentials) {
                                        credentialsManager.saveCredentials(result)
                                        Snackbar.make(
                                            requireView(),
                                            "Hello ${result.user.name}",
                                            Snackbar.LENGTH_LONG
                                        ).show()
                                    }

                                    override fun onFailure(error: AuthenticationException) {
                                        Snackbar.make(
                                            requireView(),
                                            error.getDescription(),
                                            Snackbar.LENGTH_LONG
                                        ).show()
                                    }
                                })
                        }
                    })
            }

            override fun onFailure(error: AuthenticationException) {
                Snackbar.make(
                    requireView(),
                    error.getDescription(),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        })
    }

    private fun passkeySignin() {
        authenticationApiClient.passkeyChallenge()
            .start(object : Callback<PasskeyChallenge, AuthenticationException> {
                override fun onSuccess(result: PasskeyChallenge) {
                    val passkeyChallengeResponse = result
                    val request =
                        GetPublicKeyCredentialOption(Gson().toJson(passkeyChallengeResponse.authParamsPublicKey))
                    val getCredRequest = GetCredentialRequest(
                        listOf(request)
                    )

                    credentialManager.getCredentialAsync(
                        requireContext(),
                        getCredRequest,
                        CancellationSignal(),
                        Executors.newSingleThreadExecutor(),
                        object :
                            CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                            override fun onError(e: GetCredentialException) {
                            }

                            override fun onResult(result: GetCredentialResponse) {
                                when (val credential = result.credential) {
                                    is PublicKeyCredential -> {
                                        val authRequest = Gson().fromJson(
                                            credential.authenticationResponseJson,
                                            PublicKeyCredentials::class.java
                                        )
                                        authenticationApiClient.signinWithPasskey(
                                            passkeyChallengeResponse.authSession,
                                            authRequest,
                                            "Username-Password-Authentication"
                                        )
                                            .validateClaims()
                                            .start(object :
                                                Callback<Credentials, AuthenticationException> {
                                                override fun onSuccess(result: Credentials) {
                                                    credentialsManager.saveCredentials(result)
                                                    Snackbar.make(
                                                        requireView(),
                                                        "Hello ${result.user.name}",
                                                        Snackbar.LENGTH_LONG
                                                    ).show()
                                                }

                                                override fun onFailure(error: AuthenticationException) {
                                                    Snackbar.make(
                                                        requireView(),
                                                        error.getDescription(),
                                                        Snackbar.LENGTH_LONG
                                                    ).show()
                                                }
                                            })
                                    }

                                    else -> {
                                        Snackbar.make(
                                            requireView(),
                                            "Received unrecognized credential type ${credential.type}.This shouldn't happen",
                                            Snackbar.LENGTH_LONG
                                        ).show()
                                    }
                                }
                            }
                        })
                }

                override fun onFailure(error: AuthenticationException) {
                    Snackbar.make(
                        requireView(), error.getDescription(), Snackbar.LENGTH_LONG
                    ).show()
                }
            })
    }

    private suspend fun passkeySignupAsync(email: String) {

        try {
            val challenge = authenticationApiClient.signupWithPasskey(
                UserData(email = email)
            ).await()

            val request = CreatePublicKeyCredentialRequest(
                Gson().toJson(challenge.authParamsPublicKey)
            )

            val result = credentialManager.createCredential(requireContext(), request)

            val authRequest = Gson().fromJson(
                (result as CreatePublicKeyCredentialResponse).registrationResponseJson,
                PublicKeyCredentials::class.java
            )

            val userCredential = authenticationApiClient.signinWithPasskey(
                challenge.authSession, authRequest, "Username-Password-Authentication"
            )
                .validateClaims()
                .await()

            credentialsManager.saveCredentials(userCredential)
            Snackbar.make(
                requireView(),
                "Hello ${userCredential.user.name}",
                Snackbar.LENGTH_LONG
            ).show()

        } catch (e: CreateCredentialException) {
            Snackbar.make(
                requireView(),
                e.errorMessage!!,
                Snackbar.LENGTH_LONG
            ).show()
        } catch (exception: AuthenticationException) {
            Snackbar.make(
                requireView(),
                exception.getDescription(),
                Snackbar.LENGTH_LONG
            ).show()
        }
    }

    private suspend fun passkeySigninAsync() {
        try {

            val challenge =
                authenticationApiClient.passkeyChallenge()
                    .await()

            val request = GetPublicKeyCredentialOption(Gson().toJson(challenge.authParamsPublicKey))
            val getCredRequest = GetCredentialRequest(
                listOf(request)
            )
            val result = credentialManager.getCredential(requireContext(), getCredRequest)
            when (val credential = result.credential) {
                is PublicKeyCredential -> {
                    val authRequest = Gson().fromJson(
                        credential.authenticationResponseJson,
                        PublicKeyCredentials::class.java
                    )
                    val userCredential = authenticationApiClient.signinWithPasskey(
                        challenge.authSession,
                        authRequest,
                        "Username-Password-Authentication"
                    )
                        .validateClaims()
                        .await()
                    credentialsManager.saveCredentials(userCredential)
                    Snackbar.make(
                        requireView(),
                        "Hello ${userCredential.user.name}",
                        Snackbar.LENGTH_LONG
                    ).show()
                }

                else -> {}
            }
        } catch (e: GetCredentialException) {
            Snackbar.make(
                requireView(),
                e.errorMessage!!,
                Snackbar.LENGTH_LONG
            ).show()
        } catch (exception: AuthenticationException) {
            Snackbar.make(
                requireView(),
                exception.getDescription(),
                Snackbar.LENGTH_LONG
            ).show()
        }
    }
}