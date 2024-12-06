package com.auth0.android.provider

import android.os.Parcel
import android.os.Parcelable
import android.util.Base64
import androidx.core.os.ParcelCompat
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.request.internal.GsonProvider
import com.google.gson.Gson

internal data class OAuthManagerState(
    val auth0: Auth0,
    val parameters: Map<String, String>,
    val headers: Map<String, String>,
    val requestCode: Int = 0,
    val ctOptions: CustomTabsOptions,
    val pkce: PKCE?,
    val idTokenVerificationLeeway: Int?,
    val idTokenVerificationIssuer: String?
) {

    private class OAuthManagerJson(
        val auth0ClientId: String,
        val auth0DomainUrl: String,
        val auth0ConfigurationUrl: String?,
        val parameters: Map<String, String>,
        val headers: Map<String, String>,
        val requestCode: Int = 0,
        val ctOptions: String,
        val redirectUri: String,
        val codeChallenge: String,
        val codeVerifier: String,
        val idTokenVerificationLeeway: Int?,
        val idTokenVerificationIssuer: String?
    )

    fun serializeToJson(
        gson: Gson = GsonProvider.gson,
    ): String {
        val parcel = Parcel.obtain()
        try {
            parcel.writeParcelable(ctOptions, Parcelable.PARCELABLE_WRITE_RETURN_VALUE)
            val ctOptionsEncoded = Base64.encodeToString(parcel.marshall(), Base64.DEFAULT)

            val json = OAuthManagerJson(
                auth0ClientId = auth0.clientId,
                auth0ConfigurationUrl = auth0.configurationDomain,
                auth0DomainUrl = auth0.domain,
                parameters = parameters,
                headers = headers,
                requestCode = requestCode,
                ctOptions = ctOptionsEncoded,
                redirectUri = pkce?.redirectUri.orEmpty(),
                codeVerifier = pkce?.codeVerifier.orEmpty(),
                codeChallenge = pkce?.codeChallenge.orEmpty(),
                idTokenVerificationIssuer = idTokenVerificationIssuer,
                idTokenVerificationLeeway = idTokenVerificationLeeway,
            )
            return gson.toJson(json)
        } finally {
            parcel.recycle()
        }
    }

    companion object {
        fun deserializeState(
            json: String,
            gson: Gson = GsonProvider.gson,
        ): OAuthManagerState {
            val parcel = Parcel.obtain()
            try {
                val oauthManagerJson = gson.fromJson(json, OAuthManagerJson::class.java)

                val decodedCtOptionsBytes = Base64.decode(oauthManagerJson.ctOptions, Base64.DEFAULT)
                parcel.unmarshall(decodedCtOptionsBytes, 0, decodedCtOptionsBytes.size)
                parcel.setDataPosition(0)

                val customTabsOptions = ParcelCompat.readParcelable(
                    parcel,
                    CustomTabsOptions::class.java.classLoader,
                    CustomTabsOptions::class.java
                ) ?: error("Couldn't deserialize from Parcel")

                val auth0 = Auth0.getInstance(
                    clientId = oauthManagerJson.auth0ClientId,
                    domain = oauthManagerJson.auth0DomainUrl,
                    configurationDomain = oauthManagerJson.auth0ConfigurationUrl,
                )

                return OAuthManagerState(
                    auth0 = auth0,
                    parameters = oauthManagerJson.parameters,
                    headers = oauthManagerJson.headers,
                    requestCode = oauthManagerJson.requestCode,
                    ctOptions = customTabsOptions,
                    pkce = PKCE(
                        AuthenticationAPIClient(auth0),
                        oauthManagerJson.codeVerifier,
                        oauthManagerJson.redirectUri,
                        oauthManagerJson.codeChallenge,
                        oauthManagerJson.headers,
                    ),
                    idTokenVerificationIssuer = oauthManagerJson.idTokenVerificationIssuer,
                    idTokenVerificationLeeway = oauthManagerJson.idTokenVerificationLeeway,
                )
            } finally {
                parcel.recycle()
            }
        }
    }
}
