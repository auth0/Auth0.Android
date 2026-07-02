package com.auth0.android.provider

import android.os.Parcel
import android.os.Parcelable
import android.util.Base64
import androidx.core.os.ParcelCompat
import com.auth0.android.Auth0
import com.auth0.android.request.internal.GsonProvider
import com.google.gson.Gson

internal data class PARCodeManagerState(
    val auth0: Auth0,
    val requestCode: Int,
    val requestUri: String,
    val sessionTransferToken: String?,
    val ctOptions: CustomTabsOptions
) {

    private class PARCodeManagerJson(
        val auth0ClientId: String,
        val auth0DomainUrl: String,
        val auth0ConfigurationUrl: String?,
        val requestCode: Int,
        val requestUri: String,
        val sessionTransferToken: String?,
        val ctOptions: String
    )

    fun serializeToJson(gson: Gson = GsonProvider.gson): String {
        val parcel = Parcel.obtain()
        try {
            parcel.writeParcelable(ctOptions, Parcelable.PARCELABLE_WRITE_RETURN_VALUE)
            val ctOptionsEncoded = Base64.encodeToString(parcel.marshall(), Base64.DEFAULT)

            val json = PARCodeManagerJson(
                auth0ClientId = auth0.clientId,
                auth0DomainUrl = auth0.domain,
                auth0ConfigurationUrl = auth0.configurationDomain,
                requestCode = requestCode,
                requestUri = requestUri,
                sessionTransferToken = sessionTransferToken,
                ctOptions = ctOptionsEncoded
            )
            return gson.toJson(json)
        } finally {
            parcel.recycle()
        }
    }

    companion object {
        fun deserializeState(
            json: String,
            gson: Gson = GsonProvider.gson
        ): PARCodeManagerState {
            val parcel = Parcel.obtain()
            try {
                val parsed = gson.fromJson(json, PARCodeManagerJson::class.java)

                val decodedCtOptionsBytes = Base64.decode(parsed.ctOptions, Base64.DEFAULT)
                parcel.unmarshall(decodedCtOptionsBytes, 0, decodedCtOptionsBytes.size)
                parcel.setDataPosition(0)

                val customTabsOptions = ParcelCompat.readParcelable(
                    parcel,
                    CustomTabsOptions::class.java.classLoader,
                    CustomTabsOptions::class.java
                ) ?: error("Couldn't deserialize CustomTabsOptions from Parcel")

                val auth0 = Auth0.getInstance(
                    clientId = parsed.auth0ClientId,
                    domain = parsed.auth0DomainUrl,
                    configurationDomain = parsed.auth0ConfigurationUrl
                )

                return PARCodeManagerState(
                    auth0 = auth0,
                    requestCode = parsed.requestCode,
                    requestUri = parsed.requestUri,
                    sessionTransferToken = parsed.sessionTransferToken,
                    ctOptions = customTabsOptions
                )
            } finally {
                parcel.recycle()
            }
        }
    }
}
