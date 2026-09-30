package com.auth0.android.embedded.authorize

import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException
import com.auth0.android.embedded.EmbeddedAuthError
import com.auth0.android.embedded.EmbeddedAuthException
import com.auth0.android.request.ErrorAdapter
import com.auth0.android.request.JsonAdapter
import com.auth0.android.request.internal.GsonAdapter
import com.auth0.android.request.internal.GsonAdapter.Companion.forMap
import com.auth0.android.request.internal.GsonProvider
import com.auth0.android.request.internal.ResponseUtils.isNetworkError
import com.google.gson.Gson
import java.io.IOException
import java.io.Reader

private const val ERROR_KEY = "error"
private const val ERROR_DESCRIPTION_KEY = "error_description"
private const val NEXT_KEY = "next"
private const val AUTH_SESSION_KEY = "auth_session"
private const val DEFAULT_DESCRIPTION =
    "An error occurred when trying to authenticate with the server."

private const val INSUFFICIENT_AUTHORIZATION = "insufficient_authorization"
private const val ACCESS_DENIED = "access_denied"
private const val TOO_MANY_WRONG_OTP_ATTEMPTS = "too_many_wrong_otp_attempts"
private const val CHALLENGE_EXPIRED = "challenge_expired"
private const val TOO_MANY_REQUESTS = "too_many_requests"
private const val TOO_MANY_ATTEMPTS = "too_many_attempts"
private const val TOO_MANY_LOGINS = "too_many_logins"
private const val INVALID_GRANT = "invalid_grant"
private const val TOO_MANY_REQUESTS_STATUS = 429

/** Parses the `200` body of `/e/authorize` into the code to exchange for tokens. */
internal fun authorizeCodeAdapter(gson: Gson): JsonAdapter<AuthorizeCode> =
    GsonAdapter(AuthorizeCode::class.java, gson)

/**
 * Translates every embedded-authentication error response into an [EmbeddedAuthException].
 */
internal fun embeddedAuthErrorAdapter(): ErrorAdapter<EmbeddedAuthException> {
    val mapAdapter = forMap(GsonProvider.gson)
    return object : ErrorAdapter<EmbeddedAuthException> {

        override fun fromRawResponse(
            statusCode: Int,
            bodyText: String,
            headers: Map<String, List<String>>
        ): EmbeddedAuthException {
            return if (bodyText.isBlank()) EmbeddedAuthException(
                Auth0Exception.EMPTY_BODY_ERROR,
                Auth0Exception.EMPTY_RESPONSE_BODY_DESCRIPTION,
                statusCode,
                error = EmbeddedAuthError.Unknown
            ) else EmbeddedAuthException(
                Auth0Exception.NON_JSON_ERROR,
                bodyText,
                statusCode,
                error = EmbeddedAuthError.Unknown
            )
        }

        @Throws(IOException::class)
        override fun fromJsonResponse(
            statusCode: Int,
            reader: Reader
        ): EmbeddedAuthException {
            val values = mapAdapter.fromJson(reader)
            val code = values[ERROR_KEY] as? String ?: Auth0Exception.UNKNOWN_ERROR
            val description = values[ERROR_DESCRIPTION_KEY] as? String ?: DEFAULT_DESCRIPTION
            val authSession = values[AUTH_SESSION_KEY] as? String
            @Suppress("UNCHECKED_CAST")
            val nextRaw = values[NEXT_KEY] as? List<Map<String, Any>> ?: emptyList()

            val error: EmbeddedAuthError = when {
                code == INSUFFICIENT_AUTHORIZATION ->
                    EmbeddedAuthError.InsufficientAuthorization(nextRaw.toNextActions())
                code == ACCESS_DENIED && description == TOO_MANY_WRONG_OTP_ATTEMPTS ->
                    EmbeddedAuthError.TooManyWrongOtpAttempts
                code == ACCESS_DENIED && description == CHALLENGE_EXPIRED ->
                    EmbeddedAuthError.ChallengeExpired
                code == ACCESS_DENIED ->
                    EmbeddedAuthError.AccessDenied
                statusCode == TOO_MANY_REQUESTS_STATUS && code == TOO_MANY_REQUESTS && description == TOO_MANY_ATTEMPTS ->
                    EmbeddedAuthError.TooManyAttempts
                statusCode == TOO_MANY_REQUESTS_STATUS && code == TOO_MANY_REQUESTS && description == TOO_MANY_LOGINS ->
                    EmbeddedAuthError.TooManyLogins
                code == INVALID_GRANT ->
                    EmbeddedAuthError.SessionExpired
                else ->
                    EmbeddedAuthError.Unknown
            }

            return EmbeddedAuthException(
                code,
                description,
                statusCode,
                error = error,
                authSession = authSession
            )
        }

        override fun fromException(cause: Throwable): EmbeddedAuthException {
            return if (isNetworkError(cause)) EmbeddedAuthException(
                Auth0Exception.UNKNOWN_ERROR,
                "Failed to execute the network request",
                error = EmbeddedAuthError.Network,
                cause = NetworkErrorException(cause)
            ) else EmbeddedAuthException(
                Auth0Exception.UNKNOWN_ERROR,
                DEFAULT_DESCRIPTION,
                error = EmbeddedAuthError.Unknown,
                cause = Auth0Exception(DEFAULT_DESCRIPTION, cause)
            )
        }
    }
}
