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
import com.auth0.android.result.Credentials
import com.auth0.sample.databinding.FragmentDatabaseLoginBinding
import com.google.android.material.snackbar.Snackbar

/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class DatabaseLoginFragment : Fragment() {

    private val apiClient: AuthenticationAPIClient by lazy {
        val account = Auth0("esCyeleWIb1iKJUcz6fVR4e29mEHkn0O", "lbalmaceda.auth0.com")
        account.isLoggingEnabled = true
        AuthenticationAPIClient(account)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val binding = FragmentDatabaseLoginBinding.inflate(inflater, container, false)
        binding.buttonLogin.setOnClickListener {
            val email = binding.textEmail.text.toString()
            val password = binding.textPassword.text.toString()
            makeRequest(email, password)
        }
        return binding.root
    }

    private fun makeRequest(email: String, password: String) {
        apiClient.login(email, password, "Username-Password-Authentication")
            //Additional customization to the request goes here
            .start(object : AuthenticationCallback<Credentials> {
                override fun onFailure(error: AuthenticationException) {
                    requireActivity().runOnUiThread {
                        Snackbar.make(requireView(), "Failure :(", Snackbar.LENGTH_LONG).show()
                    }
                }

                override fun onSuccess(payload: Credentials?) {
                    requireActivity().runOnUiThread {
                        Snackbar.make(requireView(), "Success :D", Snackbar.LENGTH_LONG).show()
                    }
                }
            })
    }
}