package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents a standardized error response from the My Account API.
 */
public data class ErrorResponse(
    @SerializedName("type")
    val type: String,
    @SerializedName("status")
    val status: Int,
    @SerializedName("title")
    val title: String,
    @SerializedName("detail")
    val detail: String,
    @SerializedName("validation_errors")
    val validationErrors: List<ValidationError>?
) {
    /**
     * Represents a specific validation error within an error response.
     */
    public data class ValidationError(
        @SerializedName("detail")
        val detail: String,
        @SerializedName("field")
        val field: String?,
        @SerializedName("pointer")
        val pointer: String?,
        @SerializedName("source")
        val source: String?
    )
}