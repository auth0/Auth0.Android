package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * Represents a factor that is available for a user to enroll.
 */
public data class Factor(
    @SerializedName("type")
    public val type: String,
    @SerializedName("usage")
    public val usage: List<String>?
)