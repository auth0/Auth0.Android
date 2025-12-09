package com.auth0.android.request.internal

import android.text.TextUtils
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.auth0.android.Auth0Exception
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.ParameterBuilder
import com.auth0.android.callback.Callback
import com.auth0.android.provider.IdTokenMissingException
import com.auth0.android.provider.IdTokenVerificationOptions
import com.auth0.android.provider.IdTokenVerifier
import com.auth0.android.provider.TokenValidationException
import com.auth0.android.provider.UnexpectedIdTokenException
import com.auth0.android.request.AuthenticationRequest
import com.auth0.android.request.Request
import com.auth0.android.request.RequestValidator
import com.auth0.android.result.Credentials
import java.util.Date

internal open class BaseAuthenticationRequest(
    private val request: Request<Credentials, AuthenticationException>,
    private val clientId: String, baseURL: String
) : AuthenticationRequest {

    private companion object {
        private val TAG = BaseAuthenticationRequest::class.java.simpleName
        private const val ERROR_VALUE_ID_TOKEN_VALIDATION_FAILED = "Could not verify the ID token"
    }

    private var _currentTimeInMillis: Long? = null

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var validateClaims = false

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var idTokenVerificationLeeway: Int? = null

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var idTokenVerificationIssuer: String = baseURL

    @set:VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var currentTimeInMillis: Long
        get() = if (_currentTimeInMillis != null) _currentTimeInMillis!! else System.currentTimeMillis()
        set(value) {
            _currentTimeInMillis = value
        }


    /**
     * Sets the 'grant_type' parameter
     *
     * @param grantType grant type
     * @return itself
     */
    override fun setGrantType(grantType: String): AuthenticationRequest {
        addParameter(ParameterBuilder.GRANT_TYPE_KEY, grantType)
        return this
    }

    /**
     * Sets the 'connection' parameter.
     *
     * @param connection name of the connection
     * @return itself
     */
    override fun setConnection(connection: String): AuthenticationRequest {
        addParameter(ParameterBuilder.CONNECTION_KEY, connection)
        return this
    }

    /**
     * Sets the 'realm' parameter. A realm identifies the host against which the authentication will be made, and usually helps to know which username and password to use.
     *
     * @param realm name of the realm
     * @return itself
     */
    override fun setRealm(realm: String): AuthenticationRequest {
        addParameter(ParameterBuilder.REALM_KEY, realm)
        return this
    }

    /**
     * Sets the 'scope' parameter.
     *
     * @param scope a scope value
     * @return itself
     */
    override fun setScope(scope: String): AuthenticationRequest {
        addParameter(ParameterBuilder.SCOPE_KEY, scope)
        return this
    }

    /**
     * Sets the 'audience' parameter.
     *
     * @param audience an audience value
     * @return itself
     */
    override fun setAudience(audience: String): AuthenticationRequest {
        addParameter(ParameterBuilder.AUDIENCE_KEY, audience)
        return this
    }

    override fun addValidator(validator: RequestValidator): AuthenticationRequest {
        request.addValidator(validator)
        return this
    }

    override fun validateClaims(): AuthenticationRequest {
        this.validateClaims = true
        return this
    }

    override fun withIdTokenVerificationLeeway(leeway: Int): AuthenticationRequest {
        this.idTokenVerificationLeeway = leeway
        return this
    }

    override fun withIdTokenVerificationIssuer(issuer: String): AuthenticationRequest {
        this.idTokenVerificationIssuer = issuer
        return this
    }

    override fun addParameters(parameters: Map<String, String>): AuthenticationRequest {
        request.addParameters(parameters)
        return this
    }

    override fun addParameter(name: String, value: String): AuthenticationRequest {
        request.addParameter(name, value)
        return this
    }

    override fun addParameter(name: String, value: Any): AuthenticationRequest {
        request.addParameter(name, value)
        return this
    }

    override fun addHeader(name: String, value: String): AuthenticationRequest {
        request.addHeader(name, value)
        return this
    }

    override fun start(callback: Callback<Credentials, AuthenticationException>) {
        warnClaimValidation()
        request.start(object : Callback<Credentials, AuthenticationException> {
            override fun onSuccess(result: Credentials) {
                if (validateClaims) {
                    try {
                        verifyClaims(result.idToken)
                    } catch (e: AuthenticationException) {
                        callback.onFailure(e)
                        return
                    }
                }
                callback.onSuccess(result)
            }

            override fun onFailure(error: AuthenticationException) {
                callback.onFailure(error)
            }
        })
    }

    @Throws(Auth0Exception::class)
    override fun execute(): Credentials {
        warnClaimValidation()
        val credentials = request.execute()
        if (validateClaims) {
            verifyClaims(credentials.idToken)
        }
        return credentials
    }

    @JvmSynthetic
    @Throws(Auth0Exception::class)
    override suspend fun await(): Credentials {
        warnClaimValidation()
        val credentials = request.await()
        if (validateClaims) {
            verifyClaims(credentials.idToken)
        }
        return credentials
    }

    /**
     * Used to verify the claims from the ID Token.
     *
     * @param idToken - The ID Token obtained through authentication
     * @throws AuthenticationException - This is a exception wrapping around [TokenValidationException]
     */
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun verifyClaims(idToken: String) {
        try {
            if (TextUtils.isEmpty(idToken)) {
                throw IdTokenMissingException()
            }
            val decodedIdToken: Jwt = try {
                Jwt(idToken)
            } catch (error: Exception) {
                throw UnexpectedIdTokenException(error)
            }
            val options = IdTokenVerificationOptions(
                idTokenVerificationIssuer,
                clientId,
                null
            )
            options.clockSkew = idTokenVerificationLeeway
            options.clock = Date(currentTimeInMillis)
            IdTokenVerifier().verify(decodedIdToken, options, false)
        } catch (e: TokenValidationException) {
            throw AuthenticationException(ERROR_VALUE_ID_TOKEN_VALIDATION_FAILED, e)
        }
    }

    private fun warnClaimValidation() {
        if (!validateClaims) {
            Log.e(
                TAG,
                "The request is made without validating claims. Enable claim validation by calling AuthenticationRequest#validateClaims()"
            )
        }
    }
}