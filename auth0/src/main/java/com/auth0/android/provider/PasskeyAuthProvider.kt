package com.auth0.android.provider

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.credentials.CredentialManager
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.callback.Callback
import com.auth0.android.request.UserData
import com.auth0.android.result.Credentials
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Passkey authentication provider
 */

@Deprecated(
    """PasskeyAuthProvider is deprecated and will be removed in the next major version of the SDK.
        Use API's in [AuthenticationAPIClient] directly to support sign-in/signup with passkeys.""",
    level = DeprecationLevel.WARNING
)
public object PasskeyAuthProvider {

    private val TAG = PasskeyManager::class.simpleName

    /**
     * Initialize the PasskeyAuthProvider instance for signing up a user . Additional settings can be configured in the
     * SignupBuilder.
     *
     * @param auth0 [Auth0] instance to be used for authentication
     * @return a new builder instance to customize
     */
    @JvmStatic
    public fun signUp(auth0: Auth0): SignupBuilder {
        return SignupBuilder(auth0)
    }

    /**
     * Initialize the PasskeyAuthProvider instance for signing in a user. Additional settings can be configured in the
     * SignInBuilder
     *
     * @param auth0 [Auth0] instance to be used for authentication
     * @return a new builder instance to customize
     */
    @JvmStatic
    public fun signIn(auth0: Auth0): SignInBuilder {
        return SignInBuilder(auth0)
    }


    public class SignInBuilder internal constructor(private val auth0: Auth0) {
        private val parameters: MutableMap<String, String> = mutableMapOf()

        /**
         * Specify the scope for this request.
         *
         * @param scope to request
         * @return the current builder instance
         */
        public fun setScope(scope: String): SignInBuilder = apply {
            parameters[ParameterBuilder.SCOPE_KEY] = scope
        }

        /**
         * Specify the custom audience for this request.
         *
         * @param audience to use in this request
         * @return the current builder instance
         */
        public fun setAudience(audience: String): SignInBuilder = apply {
            parameters[ParameterBuilder.AUDIENCE_KEY] = audience
        }

        /**
         * Specify the realm for this request
         *
         * @param realm to use in this request
         * @return the current builder instance
         */
        public fun setRealm(realm: String): SignInBuilder = apply {
            parameters[ParameterBuilder.REALM_KEY] = realm
        }

        /**
         * Request user authentication using passkey. The result will be received in the callback.
         *
         * @param context context to run the authentication
         * @param callback to receive the result
         * @param executor optional executor to run the public key credential response creation
         */
        public fun start(
            context: Context,
            callback: Callback<Credentials, AuthenticationException>,
            executor: Executor = Executors.newSingleThreadExecutor()
        ) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                Log.w(TAG, "Requires Android 9 or higher to use passkey authentication ")
                val ex = AuthenticationException(
                    "Requires Android 9 or higher"
                )
                callback.onFailure(ex)
                return
            }
            val passkeyManager = PasskeyManager(
                AuthenticationAPIClient(auth0), CredentialManager.create(context)
            )
            passkeyManager.signin(
                context, parameters[ParameterBuilder.REALM_KEY], parameters, callback, executor
            )
        }
    }


    public class SignupBuilder internal constructor(private val auth0: Auth0) {
        private var username: String? = null
        private var email: String? = null
        private var name: String? = null
        private var phoneNumber: String? = null

        private val parameters: MutableMap<String, String> = mutableMapOf()

        /**
         * Specify the realm for this request
         *
         * @param realm to use in this request
         * @return the current builder instance
         */
        public fun setRealm(realm: String): SignupBuilder = apply {
            parameters[ParameterBuilder.REALM_KEY] = realm
        }

        /**
         * Specify the email for the user.
         * Email can be optional,required or forbidden depending on the attribute configuration for the database
         *
         * @param email to be set
         * @return the current builder instance
         */
        public fun setEmail(email: String): SignupBuilder = apply {
            this.email = email
        }

        /**
         * Specify the username for the user.
         * Username can be optional,required or forbidden depending on the attribute configuration for the database
         *
         * @param username to be set
         * @return the current builder instance
         */
        public fun setUserName(username: String): SignupBuilder = apply {
            this.username = username
        }

        /**
         * Specify the name for the user.
         * Name can be optional,required or forbidden depending on the attribute configuration for the database
         *
         * @param name to be set
         * @return the current builder instance
         */
        public fun setName(name: String): SignupBuilder = apply {
            this.name = name
        }

        /**
         * Specify the phone number for the user
         * Phone number can be optional,required or forbidden depending on the attribute configuration for the database
         *
         * @param number to be set
         * @return the current builder instance
         */
        public fun setPhoneNumber(number: String): SignupBuilder = apply {
            this.phoneNumber = number
        }

        /**
         * Specify the scope for this request.
         *
         * @param scope to request
         * @return the current builder instance
         */
        public fun setScope(scope: String): SignupBuilder = apply {
            parameters[ParameterBuilder.SCOPE_KEY] = scope
        }

        /**
         * Specify the custom audience for this request.
         *
         * @param audience to use in this request
         * @return the current builder instance
         */
        public fun setAudience(audience: String): SignupBuilder = apply {
            parameters[ParameterBuilder.AUDIENCE_KEY] = audience
        }

        /**
         * Request user signup and authentication using passkey. The result will be received in the callback.
         *
         * @param context context to run the authentication
         * @param callback to receive the result
         * @param executor optional executor to run the public key credential response creation
         */
        public fun start(
            context: Context,
            callback: Callback<Credentials, AuthenticationException>,
            executor: Executor = Executors.newSingleThreadExecutor()
        ) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                Log.w(TAG, "Requires Android 9 or higher to use passkey authentication ")
                val ex = AuthenticationException(
                    "Requires Android 9 or higher"
                )
                callback.onFailure(ex)
                return
            }
            val passkeyManager = PasskeyManager(
                AuthenticationAPIClient(auth0), CredentialManager.create(context)
            )
            val userData = UserData(email, phoneNumber, username, name)
            passkeyManager.signup(
                context,
                userData,
                parameters[ParameterBuilder.REALM_KEY],
                parameters,
                callback,
                executor
            )
        }
    }
}