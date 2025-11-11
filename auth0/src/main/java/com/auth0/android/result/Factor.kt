package com.auth0.android.result

import com.google.gson.annotations.SerializedName

public data class Factor(
    @SerializedName("type")
    public val type: String,
    @SerializedName("usage")
    public val usage: List<String>?
)