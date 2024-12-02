package com.auth0.android.provider

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.CancellationSignal
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.request.PublicKeyCredentials
import com.auth0.android.request.UserData
import com.auth0.android.result.Credentials
import com.auth0.android.result.PasskeyChallenge
import com.auth0.android.result.PasskeyRegistrationChallenge
import com.google.gson.Gson
import java.util.concurrent.Executor
import java.util.concurrent.Executors


internal class PasskeyManager(
    private val authenticationAPIClient: AuthenticationAPIClient,
    private val credentialManager: CredentialManager
) {

    private val TAG = PasskeyManager::class.simpleName

    @RequiresApi(api = Build.VERSION_CODES.P)
    @SuppressLint("PublicKeyCredential")
    fun signup(
        context: Context,
        userData: UserData,
        realm: String?,
        parameters: Map<String, String>,
        callback: Callback<Credentials, AuthenticationException>,
        executor: Executor = Executors.newSingleThreadExecutor()
    ) {
        authenticationAPIClient.signupWithPasskey(userData, realm)
            .addParameters(parameters)
            .start(object : Callback<PasskeyRegistrationChallenge, AuthenticationException> {
                override fun onSuccess(result: PasskeyRegistrationChallenge) {
                    val pasKeyRegistrationResponse = result
                    val request = CreatePublicKeyCredentialRequest(
                        Gson().toJson(
                            pasKeyRegistrationResponse.authParamsPublicKey
                        )
                    )
                    var response: CreatePublicKeyCredentialResponse?

                    credentialManager.createCredentialAsync(context,
                        request,
                        CancellationSignal(),
                        executor,
                        object :
                            CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {

                            override fun onError(e: CreateCredentialException) {
                                Log.w(TAG, "Error while creating passkey")
                                callback.onFailure(handleCreationFailure(e))
                            }

                            override fun onResult(result: CreateCredentialResponse) {

                                response = result as CreatePublicKeyCredentialResponse
                                val authRequest = Gson().fromJson(
                                    response?.registrationResponseJson,
                                    PublicKeyCredentials::class.java
                                )

                                authenticationAPIClient.signinWithPasskey(
                                    pasKeyRegistrationResponse.authSession,
                                    authRequest,
                                    realm
                                )
                                    .validateClaims()
                                    .addParameters(parameters)
                                    .start(callback)
                            }
                        })

                }

                override fun onFailure(error: AuthenticationException) {
                    callback.onFailure(error)
                }
            })

    }


    @RequiresApi(api = Build.VERSION_CODES.P)
    fun signin(
        context: Context,
        realm: String?,
        parameters: Map<String, String>,
        callback: Callback<Credentials, AuthenticationException>,
        executor: Executor = Executors.newSingleThreadExecutor()
    ) {
        authenticationAPIClient.passkeyChallenge(realm)
            .start(object : Callback<PasskeyChallenge, AuthenticationException> {
                override fun onSuccess(result: PasskeyChallenge) {
                    val passkeyChallengeResponse = result
                    val request =
                        GetPublicKeyCredentialOption(Gson().toJson(passkeyChallengeResponse.authParamsPublicKey))
                    val getCredRequest = GetCredentialRequest(
                        listOf(request)
                    )
                    credentialManager.getCredentialAsync(context,
                        getCredRequest,
                        CancellationSignal(),
                        executor,
                        object :
                            CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                            override fun onError(e: GetCredentialException) {
                                Log.w(TAG, "Error while fetching public key credential")
                                callback.onFailure(handleGetCredentialFailure(e))
                            }

                            override fun onResult(result: GetCredentialResponse) {
                                when (val credential = result.credential) {
                                    is PublicKeyCredential -> {
                                        val authRequest = Gson().fromJson(
                                            credential.authenticationResponseJson,
                                            PublicKeyCredentials::class.java
                                        )
                                        authenticationAPIClient.signinWithPasskey(
                                            passkeyChallengeResponse.authSession,
                                            authRequest,
                                            realm
                                        )
                                            .validateClaims()
                                            .addParameters(parameters)
                                            .start(callback)
                                    }

                                    else -> {
                                        Log.w(
                                            TAG,
                                            "Received unrecognized credential type ${credential.type}.This shouldn't happen"
                                        )
                                        callback.onFailure(AuthenticationException("Received unrecognized credential type ${credential.type}"))
                                    }
                                }
                            }
                        })

                }

                override fun onFailure(error: AuthenticationException) {
                    callback.onFailure(error)
                }
            })

    }

    private fun handleCreationFailure(exception: CreateCredentialException): AuthenticationException {
        return when (exception) {

            is CreateCredentialCancellationException -> {
                AuthenticationException(
                    AuthenticationException.ERROR_VALUE_AUTHENTICATION_CANCELED,
                    "The user cancelled passkey authentication operation."
                )
            }

            is CreateCredentialInterruptedException -> {
                AuthenticationException(
                    "Passkey authentication was interrupted. Please retry the call."
                )
            }

            is CreateCredentialProviderConfigurationException -> {
                AuthenticationException(
                    "Provider configuration dependency is missing. Ensure credentials-play-services-auth dependency is added."
                )
            }

            else -> {
                Log.w(TAG, "Unexpected exception type ${exception::class.java.name}")
                AuthenticationException(
                    "An error occurred when trying to authenticate with passkey"
                )
            }
        }
    }

    private fun handleGetCredentialFailure(exception: GetCredentialException): AuthenticationException {

        return when (exception) {
            is GetCredentialCancellationException -> {
                AuthenticationException(
                    AuthenticationException.ERROR_VALUE_AUTHENTICATION_CANCELED,
                    "The user cancelled passkey authentication operation."
                )
            }

            is GetCredentialInterruptedException -> {
                AuthenticationException(
                    "Passkey authentication was interrupted. Please retry the call."
                )
            }

            is GetCredentialUnsupportedException -> {
                AuthenticationException(
                    "Credential manager is unsupported. Please update the device."
                )
            }


            is NoCredentialException -> {
                AuthenticationException(
                    "No viable credential is available for the user"
                )
            }


            else -> {
                Log.w(TAG, "Unexpected exception type ${exception::class.java.name}")
                AuthenticationException(
                    "An error occurred when trying to authenticate with passkey"
                )
            }
        }
    }

}