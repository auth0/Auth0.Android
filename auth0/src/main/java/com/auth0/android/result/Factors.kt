package com.auth0.android.result

import com.google.gson.annotations.SerializedName

/**
 * A wrapper class for the list of factors returned by the API.
 */
public data class Factors(
    @SerializedName("factors")
    public val factors: List<Factor>
)