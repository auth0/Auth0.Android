package com.auth0.android.request.internal.validator

import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.RequestValidator
import java.net.URI

/**
 * Client side validation for custom token exchange
 */
public class CustomTokenExchangeValidator : RequestValidator {

    private val reservedNameSpace = listOf(
        "http://auth0.com",
        "https://auth0.com",
        "http://okta.com",
        "https://okta.com",
        "urn:ietf",
        "urn:auth0",
        "urn:okta"
    )

    override fun validate(options: RequestOptions) {
        val subjectTokenType = options.parameters["subject_token_type"] as String

        // Check if it's a reserved namespace
        if (reservedNameSpace.contains(subjectTokenType)) {
            throw AuthenticationException(
                "Invalid URI", IllegalArgumentException(
                    "The passed URI is a reserved namespace and cannot be used"
                )
            )
        }

        // If it starts with http:// or https://, validate it as a URI
        if (subjectTokenType.startsWith(
                "http://",
                ignoreCase = true
            ) || subjectTokenType.startsWith("https://", ignoreCase = true)
        ) {
            runCatching {
                URI(subjectTokenType)
            }.onFailure { error ->
                throw AuthenticationException(
                    "Invalid URI", IllegalArgumentException(
                        "The subject_token_type is not a valid URI: ${error.message}"
                    )
                )
            }
        }
    }
}