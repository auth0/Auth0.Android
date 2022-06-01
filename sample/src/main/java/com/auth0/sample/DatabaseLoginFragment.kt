package com.auth0.sample

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.storage.CredentialsManager
import com.auth0.android.authentication.storage.SecureCredentialsManager
import com.auth0.android.authentication.storage.SharedPreferencesStorage
import com.auth0.android.callback.Callback
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.request.DefaultClient
import com.auth0.android.result.Credentials
import com.auth0.android.result.UserProfile
import com.auth0.sample.databinding.FragmentDatabaseLoginBinding
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.lang.Exception

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class DatabaseLoginFragment : Fragment() {

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

    lateinit var manager: SecureCredentialsManager

    private val apiClient: AuthenticationAPIClient by lazy {
        AuthenticationAPIClient(account)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val binding = FragmentDatabaseLoginBinding.inflate(inflater, container, false)
        val authentication = AuthenticationAPIClient(account)
        val storage = SharedPreferencesStorage(requireContext())
        manager = SecureCredentialsManager(requireContext(), authentication, storage)
        manager.requireAuthentication(requireActivity(), 201, "Hi Hello", "Poovam");
        binding.buttonLogin.setOnClickListener {
            val email = binding.textEmail.text.toString()
            val password = binding.textPassword.text.toString()
            dbLogin(email, password)
        }
        binding.buttonWebAuth.setOnClickListener {
            webAuth()
        }
        binding.buttonWebLogout.setOnClickListener {
            webLogout()
        }
        return binding.root
    }

    private fun dbLogin(email: String, password: String) {
        val a = apiClient.login(email, password, "Username-Password-Authentication")
        GlobalScope.launch {
            try {
                val b = a.await()
                println(b)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
            //Additional customization to the request goes here

    }

    private fun getCred(email: String, password: String) {
        GlobalScope.launch {
            val a = manager.awaitCredentials()
            println(a)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        manager.checkAuthenticationResult(requestCode, resultCode)
    }

    private fun webAuth() {
        WebAuthProvider.login(account)
            .withScheme(getString(R.string.com_auth0_scheme))
            .start(requireContext(), object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    Snackbar.make(
                        requireView(),
                        "Success: ${result.accessToken}",
                        Snackbar.LENGTH_LONG
                    ).show()
//                    manager.saveCredentials(result)
                    apiClient.userInfo(result.accessToken).start(object : Callback<UserProfile, AuthenticationException>{
                        override fun onSuccess(result: UserProfile) {
                            val a = result
                            println(a)
                        }

                        override fun onFailure(error: AuthenticationException) {
                            TODO("Not yet implemented")
                        }

                    })
                }

                override fun onFailure(error: AuthenticationException) {
                    val message =
                        if (error.isCanceled) "Browser was closed" else error.getDescription()
                    Snackbar.make(requireView(), message, Snackbar.LENGTH_LONG).show()
                }
            })
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
}