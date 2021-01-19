package com.auth0.android.request.internal

import android.util.Base64
import androidx.test.espresso.matcher.ViewMatchers.assertThat
import com.auth0.android.provider.TokenValidationException
import com.google.gson.stream.MalformedJsonException
import org.hamcrest.Matchers.*
import org.hamcrest.collection.IsEmptyCollection
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.nio.charset.Charset
import java.util.*


@RunWith(RobolectricTestRunner::class)
public class JwtTest {

    @Test
    public fun shouldThrowIfLessThan3Parts() {
        Assert.assertThrows(
            "The token was expected to have 3 parts, but got 2.",
            TokenValidationException::class.java
        ) {
            Jwt("two.parts")
        }
    }

    @Test
    public fun shouldThrowIfMoreThan3Parts() {
        Assert.assertThrows(
            "The token was expected to have 3 parts, but got 4.",
            TokenValidationException::class.java
        ) {
            Jwt("this.has.four.parts")
        }
    }

    @Test
    public fun shouldThrowIfItsNotBase64Encoded() {
        Assert.assertThrows(
            "Received bytes didn't correspond to a valid Base64 encoded string.",
            IllegalArgumentException::class.java
        ) {
            Jwt("thisIsNot.Base64_Enc.oded")
        }
    }

    @Test
    public fun shouldThrowIfPayloadHasInvalidJSONFormat() {
        Assert.assertThrows(
            "The token's payload had an invalid JSON format.",
            MalformedJsonException::class.java
        ) {
            Jwt("eyJhbGciOiJIUzI1NiJ9.e2F9.HtPWFL4M0n-jwSEOuBeGIscY5CvElN9O5LH_ag7jHrY")
        }
    }

    // Parts

    @Test
    public fun shouldGetParts() {
        val jwt = Jwt("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")
        assertThat(jwt, `is`(notNullValue()))
        assertThat(
            jwt.parts,
            `is`(
                arrayContaining(
                    "eyJhbGciOiJIUzI1NiJ9",
                    "e30",
                    "XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"
                )
            )
        )
    }


    // Public Claims

    @Test
    public fun shouldGetIssuer() {
        val jwt =
            Jwt("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ");
        assertThat(jwt, `is`(notNullValue()))
        assertThat(jwt.getIssuer(), `is`("John Doe"))
    }

    @Test
    public fun shouldGetNullIssuerIfMissing() {
        val jwt = Jwt("eyJhbGciOiJIUzI1NiJ9.e30.something");
        assertThat(jwt, `is`(notNullValue()))

        assertThat(jwt.getIssuer(), `is`(nullValue()))
    }

    @Test
    public fun shouldGetSubject() {
        val jwt =
            Jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs");
        assertThat(jwt, `is`(notNullValue()))
        assertThat(jwt.getSubject(), `is`("Tok3ns"))
    }

    @Test
    public fun shouldGetNullSubjectIfMissing() {
        val jwt = Jwt("eyJhbGciOiJIUzI1NiJ9.e30.something");
        assertThat(jwt, `is`(notNullValue()))

        assertThat(jwt.getSubject(), `is`(nullValue()))
    }

    @Test
    public fun shouldGetArrayAudience() {
        val jwt =
            Jwt("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4");
        assertThat(jwt, `is`(notNullValue()))
        assertThat(jwt.getAudience(), `is`(hasSize(3)))
        assertThat(jwt.getAudience(), `is`(hasItems("Hope", "Travis", "Solomon")))
    }

    @Test
    public fun shouldGetStringAudience() {
        val jwt =
            Jwt("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc");
        assertThat(jwt, `is`(notNullValue()))
        assertThat(jwt.getAudience(), `is`(hasSize(1)))
        assertThat(jwt.getAudience(), `is`(hasItems("Jack Reyes")))
    }

    @Test
    public fun shouldGetEmptyListAudienceIfMissing() {
        val jwt = Jwt("eyJhbGciOiJIUzI1NiJ9.e30.something");
        assertThat(jwt, `is`(notNullValue()))

        assertThat(jwt.getAudience(), IsEmptyCollection.empty())
    }

    @Test
    public fun shouldDeserializeDatesUsingLong() {
        val jwt =
            Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIxNDc0OTM2NDcsImF1dGhfdGltZSI6MjE0NzQ5MzY0NywiZXhwIjoyMTQ3NDkzNjQ3fQ.N4xAEtbb9pv_w2B7gVZZQbuRrcUJFJ_aZvhi8rlnw30");
        assertThat(jwt, `is`(notNullValue()))

        val secs = Integer.MAX_VALUE + 10000L;
        val expectedDate = Date(secs * 1000);
        assertThat(jwt.getIssuedAt(), `is`(expectedDate))
        assertThat(jwt.getExpiresAt(), `is`(expectedDate))
        assertThat(jwt.getAuthenticationTime(), `is`(expectedDate))
    }

    @Test
    public fun shouldGetExpirationTime() {
        val jwt =
            Jwt("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NzY3MjcwODZ9.HF2RrW-0L0nTIgiM8Ov7MWabIEZl4PQs07E43BphnXw");
        assertThat(jwt, `is`(notNullValue()))
        assertThat(jwt.getExpiresAt(), `is`(instanceOf(Date::class.java)))
        val ms = 1476727086L * 1000;
        val expectedDate = Date(ms)
        assertThat(jwt.getExpiresAt(), `is`(notNullValue()))
        assertThat(jwt.getExpiresAt(), `is`(equalTo(expectedDate)))
    }

    @Test
    public fun shouldGetNullExpirationTimeIfMissing() {
        val jwt = Jwt("eyJhbGciOiJIUzI1NiJ9.e30.something");
        assertThat(jwt, `is`(notNullValue()))

        assertThat(jwt.getExpiresAt(), `is`(nullValue()))
    }

    @Test
    public fun shouldGetIssuedAt() {
        val jwt =
            Jwt("eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NzY3MjcwODZ9.HcNvTtoB-Wj4KUqsl9y2u2f2Ve2JrlL1X4xIPwGNy68");
        assertThat(jwt, `is`(notNullValue()))
        assertThat(
            jwt.getIssuedAt(), `is`(instanceOf(Date::class.java))
        )
        val ms = 1476727086L * 1000;
        val expectedDate = Date(ms);
        assertThat(jwt.getIssuedAt(), `is`(notNullValue()))
        assertThat(jwt.getIssuedAt(), `is`(equalTo(expectedDate)))
    }

    @Test
    public fun shouldGetNullIssuedAtIfMissing() {
        val jwt = Jwt("eyJhbGciOiJIUzI1NiJ9.e30.something");
        assertThat(jwt, `is`(notNullValue()))

        assertThat(jwt.getIssuedAt(), `is`(nullValue()))
    }
    //Helper Methods

    /**
     * Creates a new JWT with custom time claims.
     *
     * @param iatMs iat value in MILLISECONDS
     * @param expMs exp value in MILLISECONDS
     * @return a JWT
     */
    private fun customTimeJWT(iatMs: Long?, expMs: Long?): Jwt {
        val header = encodeString("{}");
        val bodyBuilder = StringBuilder("{");
        if (iatMs != null) {
            val iatSeconds = iatMs / 1000;
            bodyBuilder.append("\"iat\":\"").append(iatSeconds).append("\"");
        }
        if (expMs != null) {
            if (iatMs != null) {
                bodyBuilder.append(",");
            }
            val expSeconds = expMs / 1000;
            bodyBuilder.append("\"exp\":\"").append(expSeconds).append("\"");
        }
        bodyBuilder.append("}");
        val body: String = encodeString(bodyBuilder.toString());
        val signature: String = "sign";
        return Jwt(String.format("%s.%s.%s", header, body, signature));
    }

    private fun encodeString(source: String): String {
        val bytes = Base64.encode(
            source.toByteArray(Charset.defaultCharset()),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
        return String(bytes, Charset.defaultCharset())
    }

}