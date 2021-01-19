package com.auth0.sample

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.AuthenticationCallback
import com.auth0.android.callback.Callback
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.request.DefaultClient
import com.auth0.android.result.Credentials
import com.auth0.sample.databinding.FragmentDatabaseLoginBinding
import com.google.android.material.snackbar.Snackbar

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class DatabaseLoginFragment : Fragment() {

    private val account: Auth0 by lazy {
        val account = Auth0("esCyeleWIb1iKJUcz6fVR4e29mEHkn0O", "lbalmaceda.auth0.com")
        // Only enable network traffic logging on production environments!
        account.networkingClient = DefaultClient(enableLogging = true)
        account
    }

    private val apiClient: AuthenticationAPIClient by lazy {
        AuthenticationAPIClient(account)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val binding = FragmentDatabaseLoginBinding.inflate(inflater, container, false)
        binding.buttonLogin.setOnClickListener {
            val email = binding.textEmail.text.toString()
            val password = binding.textPassword.text.toString()
            dbLogin(email, password)
        }
        binding.buttonWebAuth.setOnClickListener {
            webAuth()
        }
        return binding.root
    }

    private fun dbLogin(email: String, password: String) {
        apiClient.login(email, password, "Username-Password-Authentication")
            //Additional customization to the request goes here
            .start(object : AuthenticationCallback<Credentials> {
                override fun onFailure(error: AuthenticationException) {
                    Snackbar.make(requireView(), error.getDescription(), Snackbar.LENGTH_LONG)
                        .show()
                }

                override fun onSuccess(payload: Credentials?) {
                    Snackbar.make(
                        requireView(),
                        "Success: ${payload!!.accessToken}",
                        Snackbar.LENGTH_LONG
                    ).show()
                }
            })
    }

    private fun webAuth() {
        WebAuthProvider.login(account)
            .start(requireContext(), object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(payload: Credentials?) {
                    Snackbar.make(
                        requireView(),
                        "Success: ${payload!!.accessToken}",
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