package com.auth0.android.provider

import com.auth0.android.Auth0Exception

/**
 * Exception thrown when the validation of the ID token failed.
 * This class should not be constructed, only a sub class with the exception details should beprovided
 */
public open class TokenValidationException @JvmOverloads protected constructor(
    message: String,
    cause: Throwable? = null
) : Auth0Exception(message, cause)

/**
 * This Exception is thrown when Issuer (iss) claim is missing in the ID Token
 */
public class IssClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Issuer (iss) claim must be a string present in the ID token"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the Issuer (iss) claim found in the ID token is not the
 * one that was expected
 */
public class IssClaimMismatchException internal constructor(expected: String, received: String?) :
    TokenValidationException(message(expected, received)) {
    private companion object {
        private fun message(expected: String, received: String?): String =
            "Issuer (iss) claim mismatch in the ID token, expected \"$expected\", found \"$received\""
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Subject (sub) claim is missing in the ID Token
 */
public class SubClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Subject (sub) claim must be a string present in the ID token"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Audience (aud) claim is missing in the ID Token
 */
public class AudClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Audience (aud) claim must be a string or array of strings present in the ID token"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the Audience (aud) claim found in the ID token is not the
 * one that was expected
 */
public class AudClaimMismatchException internal constructor(expected: String, received: List<String>) :
    TokenValidationException(message(expected, received)) {
    private companion object {
        private fun message(expected: String, received: List<String>): String =
            "Audience (aud) claim mismatch in the ID token; expected \"$expected\" but was not one of \"$received\""
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Expiration Time (exp) claim is missing in the ID Token
 */
public class ExpClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Expiration Time (exp) claim must be a number present in the ID token"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the ID Token is expired.
 */
public class IdTokenExpiredException internal constructor(expected: Long, received: Long?) :
    TokenValidationException(message(expected, received)) {
    private companion object {
        private fun message(nowInSeconds: Long, expInSeconds: Long?): String =
            "Expiration Time (exp) claim error in the ID token; current time ($nowInSeconds) is after expiration time ($expInSeconds)"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Issued At (iat) claim is missing in the ID Token
 */
public class IatClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Issued At (iat) claim must be a number present in the ID token"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Nonce (nonce) claim is missing in the ID Token
 */
public class NonceClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Nonce (nonce) claim must be a string present in the ID token"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the Nonce (nonce) claim found in the ID token is not the
 * one that was expected
 */
public class NonceClaimMismatchException internal constructor(expected: String?, received: String?) :
    TokenValidationException(message(expected, received)) {
    private companion object {
        private fun message(expected: String?, received: String?): String =
            "Nonce (nonce) claim mismatch in the ID token; expected \"$expected\", found \"$received\""
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Organization Id (org_id) claim is missing in the ID Token
 */
public class OrgClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Organization Id (org_id) claim must be a string present in the ID token"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the Organization Id (org_id) claim found in the ID token is not the
 * one that was expected
 */
public class OrgClaimMismatchException internal constructor(expected: String?, received: String?) :
    TokenValidationException(message(expected, received)) {
    private companion object {
        private fun message(expected: String?, received: String?): String =
            "Organization Id (org_id) claim mismatch in the ID token; expected \"$expected\", found \"$received\""
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Authorized Party (azp) claim is missing in the ID Token
 */
public class AzpClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the Authorized Party (azp) claim found in the ID token is not the
 * one that was expected
 */
public class AzpClaimMismatchException internal constructor(expected: String, received: String?) :
    TokenValidationException(message(expected, received)) {
    private companion object {
        private fun message(expected: String, received: String?): String =
            "Authorized Party (azp) claim mismatch in the ID token; expected \"$expected\", found \"$received\""
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when Authentication Time (auth_time) claim is missing in the ID Token
 */
public class AuthTimeClaimMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the Authentication Time (auth_time) claim found in the ID token is not the
 * one that was expected
 */
public class AuthTimeClaimMismatchException internal constructor(expected: Long, received: Long?) :
    TokenValidationException(message(expected, received)) {
    private companion object {
        private fun message(nowInSeconds: Long, expInSeconds: Long?): String =
            "Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time ($nowInSeconds) is after last auth at ($expInSeconds)"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * Public key for the provided Key ID (kid) is not found
 */
public class PublicKeyNotFoundException internal constructor(keyId: String?) :
    TokenValidationException(message(keyId)) {
    private companion object {
        private fun message(keyId: String?): String =
            "Could not find a public key for kid \"$keyId\""
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * The algorithm found in the ID Token is not supported
 */
public class IdTokenAlgorithmNotSupportedException internal constructor(tokenAlgorithm: String, supportedAlgorithms: List<String>) :
    TokenValidationException(message(tokenAlgorithm, supportedAlgorithms)) {
    private companion object {
        private fun message(tokenAlgorithm: String, supportedAlgorithms: List<String>): String {
            return if (supportedAlgorithms.size == 1) {
                "Signature algorithm of \"$tokenAlgorithm\" is not supported. Expected the ID token to be signed with ${supportedAlgorithms[0]}."
            } else {
                "Signature algorithm of \"$tokenAlgorithm\" is not supported. Expected the ID token to be signed with any of $supportedAlgorithms."
            }
        }
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * The signature found in the ID Token is not valid
 */
public class InvalidIdTokenSignatureException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Invalid ID token signature."
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when the [SignatureVerifier] is not passed. This shouldn't be normally thrown.
 * If this is thrown, it is an internal error in the SDK.
 */
public class SignatureVerifierMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "Signature Verifier should not be null"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This Exception is thrown when ID Token is missing in the ID Token
 */
public class IdTokenMissingException internal constructor() : TokenValidationException(MESSAGE) {
    private companion object {
        private const val MESSAGE = "ID token is required but missing"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}

/**
 * This exception is thrown when the ID Token is invalid and cannot be decoded
 */
public class UnexpectedIdTokenException internal constructor(cause: Throwable?) : TokenValidationException(MESSAGE, cause) {
    private companion object {
        private const val MESSAGE = "ID token could not be decoded"
    }

    /**
     * To avoid backward compatibility issue, we still have the toString conversion similar to the
     * old [TokenValidationException] that was thrown
     */
    override fun toString(): String {
        return "${this.javaClass.superclass.name}: $message"
    }
}