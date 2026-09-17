package com.auth0.android.embedded.authorize

import com.google.gson.annotations.SerializedName

internal class AuthorizeCode(
    @SerializedName("authorization_code") val authorizationCode: String
)
