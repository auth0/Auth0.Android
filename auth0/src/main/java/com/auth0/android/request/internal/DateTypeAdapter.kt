package com.auth0.android.request.internal

import com.google.gson.JsonSyntaxException
import com.google.gson.TypeAdapter
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.*

/**
 * Writes dates in UTC with an explicit offset so they survive DST transitions and device
 * time zone changes. Dates written by older SDK versions (device local time with a literal
 * 'Z' suffix) are still read as local time to preserve their original meaning. Such a value
 * inside a repeated DST hour is ambiguous and reads one hour late until it is saved again.
 *
 * Only meant for dates the SDK persists itself (e.g. stored credentials): any value ending in
 * 'Z' is treated as that legacy local-time format, not as UTC.
 *
 * @param legacyTimeZone zone used to read legacy values. Captured once, like the formatter
 * previously configured via `GsonBuilder.setDateFormat`, so a legacy value resolves to the same
 * instant for the lifetime of the adapter even if the device time zone changes.
 */
internal class DateTypeAdapter(
    private val legacyTimeZone: TimeZone = TimeZone.getDefault()
) : TypeAdapter<Date>() {

    override fun write(out: JsonWriter, value: Date?) {
        if (value == null) {
            out.nullValue()
            return
        }
        out.value(format(value))
    }

    override fun read(reader: JsonReader): Date? {
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull()
            return null
        }
        val value = reader.nextString()
        return try {
            parse(value)
        } catch (e: ParseException) {
            throw JsonSyntaxException("Failed parsing '$value' as Date", e)
        }
    }

    @Throws(ParseException::class)
    private fun parse(value: String): Date {
        if (value.endsWith("Z")) {
            val legacyFormatter = SimpleDateFormat(LEGACY_DATE_FORMAT, Locale.US)
            legacyFormatter.timeZone = legacyTimeZone
            return legacyFormatter.parse(value)
        }
        return SimpleDateFormat(DATE_FORMAT, Locale.US).parse(value)
    }

    internal companion object {
        private const val DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        private const val LEGACY_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"

        fun format(date: Date): String {
            val formatter = SimpleDateFormat(DATE_FORMAT, Locale.US)
            formatter.timeZone = TimeZone.getTimeZone("UTC")
            return formatter.format(date)
        }
    }
}
