package com.auth0.android.embedded.authorize

/** How a phone one-time code is delivered. */
internal enum class PhoneDeliveryMethod(val value: String) {
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
