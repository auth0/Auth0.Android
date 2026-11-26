package com.auth0.android.request.internal

import com.auth0.android.result.APICredentials
import com.auth0.android.result.Credentials
import com.auth0.android.result.CredentialsMock
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonSyntaxException
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.nullValue
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.*

public class DateTypeAdapterTest {

    private lateinit var gson: Gson
    private lateinit var defaultTimeZone: TimeZone

    @Before
    public fun setUp() {
        defaultTimeZone = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Amsterdam"))
        gson = GsonProvider.gson
    }

    @After
    public fun tearDown() {
        TimeZone.setDefault(defaultTimeZone)
    }

    @Test
    public fun shouldWriteDateInUtcWithExplicitOffset() {
        // 2026-10-25T00:35:16Z, which is 02:35:16 CEST in Amsterdam
        assertThat(gson.toJson(Date(DST_REPEATED_HOUR_MS)), `is`("\"2026-10-25T00:35:16.000+0000\""))
    }

    @Test
    public fun shouldRoundTripDateInsideRepeatedDstHour() {
        val date = Date(DST_REPEATED_HOUR_MS)
        val parsed = gson.fromJson(gson.toJson(date), Date::class.java)
        assertThat(parsed, `is`(date))
    }

    @Test
    public fun shouldRoundTripDateAcrossTimeZoneChange() {
        val date = Date(DST_REPEATED_HOUR_MS)
        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Kolkata"))
        val json = gson.toJson(date)
        TimeZone.setDefault(TimeZone.getTimeZone("America/New_York"))
        assertThat(gson.fromJson(json, Date::class.java), `is`(date))
    }

    @Test
    public fun shouldReadLegacyFormatAsLocalTime() {
        // Older SDK versions wrote local wall-clock time followed by a literal 'Z'.
        // 2026-10-24T12:00 CEST is 10:00 UTC.
        val parsed = gsonWithAdapter(DateTypeAdapter(AMSTERDAM))
            .fromJson("\"2026-10-24T12:00:00.000Z\"", Date::class.java)
        assertThat(parsed, `is`(Date(1792836000000L)))
    }

    @Test
    public fun shouldKeepReadingLegacyFormatInCapturedZoneAfterDefaultZoneChange() {
        // Adapter created while the default zone is Europe/Amsterdam (see setUp)
        val adapterGson = gsonWithAdapter(DateTypeAdapter())
        val before = adapterGson.fromJson("\"2026-10-24T12:00:00.000Z\"", Date::class.java)
        TimeZone.setDefault(TimeZone.getTimeZone("America/New_York"))
        val after = adapterGson.fromJson("\"2026-10-24T12:00:00.000Z\"", Date::class.java)
        assertThat(before, `is`(Date(1792836000000L)))
        assertThat(after, `is`(before))
    }

    @Test
    public fun shouldReadLegacyValueInsideRepeatedDstHourOneHourLate() {
        // Known limitation: the legacy format never stored the offset, so a local time in the
        // repeated hour resolves to its second occurrence (CET), one hour after the real instant.
        // It is corrected the next time the value is saved in the new format.
        val parsed = gsonWithAdapter(DateTypeAdapter(AMSTERDAM))
            .fromJson("\"2026-10-25T02:35:16.000Z\"", Date::class.java)
        assertThat(parsed, `is`(Date(DST_REPEATED_HOUR_MS + ONE_HOUR_MS)))
    }

    @Test
    public fun shouldReadDateWithNonUtcOffset() {
        val parsed = gson.fromJson("\"2026-10-25T03:35:16.000+0300\"", Date::class.java)
        assertThat(parsed, `is`(Date(DST_REPEATED_HOUR_MS)))
    }

    @Test
    public fun shouldReadAndWriteNull() {
        assertThat(gson.fromJson("null", Date::class.java), `is`(nullValue()))
        assertThat(gson.toJson(null, Date::class.java), `is`("null"))
    }

    @Test
    public fun shouldFailOnInvalidDate() {
        Assert.assertThrows(JsonSyntaxException::class.java) {
            gson.fromJson("\"not-a-date\"", Date::class.java)
        }
    }

    @Test
    public fun shouldRoundTripCredentialsExpiresAtInsideRepeatedDstHour() {
        val expiresAt = Date(DST_REPEATED_HOUR_MS)
        val credentials: Credentials =
            CredentialsMock.create("id", "access", "bearer", "refresh", expiresAt, "openid")
        val parsed = gson.fromJson(gson.toJson(credentials), Credentials::class.java)
        assertThat(parsed.expiresAt, `is`(expiresAt))
    }

    @Test
    public fun shouldRoundTripApiCredentialsExpiresAtInsideRepeatedDstHour() {
        val expiresAt = Date(DST_REPEATED_HOUR_MS)
        val apiCredentials = APICredentials("access", "bearer", expiresAt, "read:data")
        val parsed = gson.fromJson(gson.toJson(apiCredentials), APICredentials::class.java)
        assertThat(parsed.expiresAt, `is`(expiresAt))
    }

    private fun gsonWithAdapter(adapter: DateTypeAdapter): Gson =
        GsonBuilder().registerTypeAdapter(Date::class.java, adapter).create()

    private companion object {
        // 2026-10-25T00:35:16Z: inside the first occurrence of the repeated 02:00-03:00 hour in Europe/Amsterdam
        private const val DST_REPEATED_HOUR_MS = 1792888516000L
        private const val ONE_HOUR_MS = 3600000L
        private val AMSTERDAM: TimeZone = TimeZone.getTimeZone("Europe/Amsterdam")
    }
}
