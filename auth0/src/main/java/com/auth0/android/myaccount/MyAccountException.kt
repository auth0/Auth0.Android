package com.auth0.android.myaccount

import com.auth0.android.Auth0Exception
import com.auth0.android.NetworkErrorException

public class MyAccountException @JvmOverloads constructor(
    message: String,
    exception: Auth0Exception? = null
) : Auth0Exception(message, exception) {

    private var code: String? = null
    private var description: String? = null


    /**
     * Http Response status code. Can have value of 0 if not set.
     *
     * @return the status code.
     */
    public var statusCode: Int = 0
        private set
    private var values: Map<String, Any>? = null


    public val type: String?
        get() = values?.get("type") as? String
    public var status: Int = 0
        private set
    public val title: String?
        get() = values?.get("title") as? String
    public val detail: String?
        get() = values?.get("detail") as? String
    public val validationErrors: List<ValidationError>?
        get() = (values?.get("validation_errors") as? List<Map<String, String>>)?.map {
            ValidationError(
                it["detail"],
                it["field"],
                it["pointer"],
                it["source"]
            )
        }

    public constructor(payload: String?, statusCode: Int) : this(DEFAULT_MESSAGE) {
        code = if (payload != null) NON_JSON_ERROR else EMPTY_BODY_ERROR
        description = payload ?: EMPTY_RESPONSE_BODY_DESCRIPTION
        this.statusCode = statusCode
    }

    public constructor(values: Map<String, Any>) : this(DEFAULT_MESSAGE) {
        this.values = values
        val codeValue =
            (if (values.containsKey(ERROR_KEY)) values[ERROR_KEY] else values[CODE_KEY]) as String?
        code = codeValue ?: UNKNOWN_ERROR
        description =
            (if (values.containsKey(DESCRIPTION_KEY)) values[DESCRIPTION_KEY] else values[ERROR_DESCRIPTION_KEY]) as String?
    }

    /**
     * Auth0 error code if the server returned one or an internal library code (e.g.: when the server could not be reached)
     *
     * @return the error code.
     */
    @Suppress("MemberVisibilityCanBePrivate")
    public fun getCode(): String {
        return if (code != null) code!! else UNKNOWN_ERROR
    }

    /**
     * Description of the error.
     * important: You should avoid displaying description to the user, it's meant for debugging only.
     *
     * @return the error description.
     */
    @Suppress("unused")
    public fun getDescription(): String {
        if (description != null) {
            return description!!
        }
        return if (UNKNOWN_ERROR == getCode()) {
            String.format("Received error with code %s", getCode())
        } else "Failed with unknown error"
    }

    /**
     * Returns a value from the error map, if any.
     *
     * @param key key of the value to return
     * @return the value if found or null
     */
    public fun getValue(key: String): Any? {
        return values?.get(key)
    }

    // When the request failed due to network issues
    public val isNetworkError: Boolean
        get() = cause is NetworkErrorException


    public data class ValidationError(
        val detail: String?,
        val field: String?,
        val pointer: String?,
        val source: String?
    )

    private companion object {
        private const val ERROR_KEY = "error"
        private const val CODE_KEY = "code"
        private const val DESCRIPTION_KEY = "description"
        private const val ERROR_DESCRIPTION_KEY = "error_description"
        private const val DEFAULT_MESSAGE =
            "An error occurred when trying to authenticate with the server."
    }

}