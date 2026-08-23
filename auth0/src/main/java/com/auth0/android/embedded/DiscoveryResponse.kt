package com.auth0.android.embedded

import com.google.gson.annotations.SerializedName

/**
 * Wire representation of the `GET /e/discovery` response.
 *
 * Internal on purpose: [DiscoveryResult] is the public model, built from this by
 * [DiscoveryResponse.toDiscoveryResult]. Keeping the wire out of the public API lets the response
 * gain variants without that being a breaking change here.
 */
internal data class DiscoveryResponse(
    @SerializedName("alternatives")
    val alternatives: List<Alternative>?
)

/**
 * One entry of the wire's `alternatives` array.
 *
 * The wire is a discriminated union over six variants keyed by `grant_type`, each carrying only the
 * properties its grant needs. Modelled here as one lenient shape so that an unrecognised variant
 * deserializes instead of failing the whole response; [Alternative.toLoginOption] interprets it.
 *
 * Note `type` means different things per variant with disjoint value sets — `legacy`/`auth0` on the
 * passwordless variant, `embedded_authorize` on the authorization-code one — so it is read only
 * after selecting on [grantType], and never surfaces as a single public field.
 */
internal data class Alternative(
    @SerializedName("grant_type")
    val grantType: String?,

    @SerializedName("type")
    val type: String? = null,

    @SerializedName("connection")
    val connection: String? = null,

    @SerializedName("realm")
    val realm: String? = null,

    @SerializedName("identifier_types")
    val identifierTypes: List<String>? = null,

    @SerializedName("subject_token_type")
    val subjectTokenType: String? = null
)
