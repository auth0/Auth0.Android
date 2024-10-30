package com.auth0.android.request


import com.google.gson.annotations.SerializedName

internal data class PublicKeyCredentialResponse(
    @SerializedName("authenticatorAttachment")
    val authenticatorAttachment: String,
    @SerializedName("clientExtensionResults")
    val clientExtensionResults: ClientExtensionResults,
    @SerializedName("id")
    val id: String,
    @SerializedName("rawId")
    val rawId: String,
    @SerializedName("response")
    val response: Response,
    @SerializedName("type")
    val type: String
)


public data class Response(
    @SerializedName("attestationObject")
    val attestationObject: String,
    @SerializedName("authenticatorData")
    val authenticatorData: String,
    @SerializedName("clientDataJSON")
    val clientDataJSON: String,
    @SerializedName("transports")
    val transports: List<String>,
    @SerializedName("signature")
    val signature:String,
    @SerializedName("userHandle")
    val userHandle:String
)

public data class CredProps(
    @SerializedName("rk")
    val rk: Boolean
)

public data class ClientExtensionResults(
    @SerializedName("credProps")
    val credProps: CredProps
)