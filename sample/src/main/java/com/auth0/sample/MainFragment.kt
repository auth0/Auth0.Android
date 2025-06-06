package com.auth0.sample

import android.os.Bundle
import android.os.CancellationSignal
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.exceptions.CreateCredentialException
import androidx.fragment.app.Fragment
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.myaccount.MyAccountAPIClient
import com.auth0.android.myaccount.MyAccountException
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.request.DefaultClient
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.result.Credentials
import com.auth0.android.result.PasskeyAuthenticationMethod
import com.auth0.android.result.PasskeyEnrollmentChallenge
import com.google.android.material.snackbar.Snackbar
import com.google.gson.Gson
import java.util.concurrent.Executors


class MainFragment : Fragment() {

    private lateinit var webLoginButton: Button
    private lateinit var passkeyEnrollment: Button
    private lateinit var accessToken: TextView

    private lateinit var credentialToken: String

    private val scope =
        "openid profile email read:current_user create:me:authentication_methods update:current_user_metadata"

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

    private val credentialManager: CredentialManager by lazy {
        CredentialManager.create(requireContext())
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        webLoginButton = view.findViewById(R.id.webLogin)
        passkeyEnrollment = view.findViewById(R.id.enrollment)
        accessToken = view.findViewById(R.id.accessToken)

        webLoginButton.setOnClickListener {
            webAuth()
        }

        passkeyEnrollment.setOnClickListener {
            passkeyEnroll()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_main, container, false)
    }


    private fun webAuth() {
        WebAuthProvider.login(account)
            .withScheme(getString(R.string.com_auth0_scheme))
            .withAudience("AUDIENCE")
            .withScope(scope)
            .start(requireContext(), object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    accessToken.visibility = View.VISIBLE
                    passkeyEnrollment.visibility = View.VISIBLE
                    credentialToken = result.accessToken
                    accessToken.text = result.accessToken
                }

                override fun onFailure(error: AuthenticationException) {
                    val message =
                        if (error.isCanceled)
                            "Browser was closed"
                        else
                            error.getDescription()
                    accessToken.text = message
                }
            })
    }

    private fun passkeyEnroll() {

        if (!this::credentialToken.isInitialized) {
            Snackbar.make(
                requireView(),
                "Please login first",
                Snackbar.LENGTH_LONG
            ).show()
            return
        }
        val client = MyAccountAPIClient(account, credentialToken)
        client.passkeyEnrollmentChallenge()
            .start(object : Callback<PasskeyEnrollmentChallenge, MyAccountException> {
                override fun onSuccess(result: PasskeyEnrollmentChallenge) {
                    val challenge = result
                    val request = CreatePublicKeyCredentialRequest(
                        Gson().toJson(
                            challenge.authParamsPublicKey
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
                                val credentials = Gson().fromJson(
                                    response?.registrationResponseJson,
                                    PublicKeyCredentials::class.java
                                )

                                client.enroll(
                                    credentials,
                                    challenge
                                )
                                    .start(object :
                                        Callback<PasskeyAuthenticationMethod, MyAccountException> {
                                        override fun onSuccess(result: PasskeyAuthenticationMethod) {
                                            Snackbar.make(
                                                requireView(),
                                                "Passkey Enrolled Successfully",
                                                Snackbar.LENGTH_LONG
                                            ).show()
                                        }

                                        override fun onFailure(error: MyAccountException) {
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

                override fun onFailure(error: MyAccountException) {
                    accessToken.text = "Error: ${error.getDescription()}"
                }
            })
    }
}