package com.auth0.android.embedded.authorize

import com.auth0.android.embedded.EmbeddedAuthClient

/** How a phone one-time code is delivered, chosen when calling [EmbeddedAuthClient.challengePhone]. */
public enum class PhoneDeliveryMethod(public val value: String) {
    /** Deliver the code as an SMS text message. */
    TEXT("text"),

    /** Deliver the code by a voice call. */
    VOICE("voice");

    internal companion object {
        /** Maps the raw `delivery_method` string to a [PhoneDeliveryMethod], or `null` when absent or unrecognised. */
        fun fromValue(value: String?): PhoneDeliveryMethod? =
            entries.firstOrNull { it.value.equals(value, ignoreCase = true) }
    }
}
