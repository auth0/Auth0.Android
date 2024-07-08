package com.auth0.android.authentication.storage

import androidx.fragment.app.FragmentActivity
import com.auth0.android.callback.Callback

internal class DefaultLocalAuthenticationManagerFactory : LocalAuthenticationManagerFactory {
    override fun create(
        activity: FragmentActivity,
        authenticationOptions: LocalAuthenticationOptions,
        resultCallback: Callback<Boolean, CredentialsManagerException>
    ): LocalAuthenticationManager = LocalAuthenticationManager(
        activity = activity,
        authenticationOptions = authenticationOptions,
        resultCallback = resultCallback
    )
}