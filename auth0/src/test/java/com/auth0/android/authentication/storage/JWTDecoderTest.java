package com.auth0.android.authentication.storage;

import com.auth0.android.request.internal.Jwt;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(RobolectricTestRunner.class)
public class JWTDecoderTest {

    @Test
    public void shouldDecodeAToken() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFsaWNlIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibm9uY2UiOiJyZWFsbHkgcmFuZG9tIHRleHQiLCJpYXQiOjE1MTYyMzkwMjJ9.rYG-HEs1EKKDhwQIoEg32_p-NQzNi5rB7akqGnH_q4k";
        Jwt jwt1 = new Jwt(token);

        Jwt jwt2 = new JWTDecoder().decode(token);

        //Header claims
        assertThat(jwt1.getAlgorithm(), is("HS256"));
        assertThat(jwt1.getKeyId(), is("alice"));
        assertThat(jwt2.getAlgorithm(), is("HS256"));
        assertThat(jwt2.getKeyId(), is("alice"));

        //Payload claims
        assertThat(jwt1.getSubject(), is("1234567890"));
        assertThat(jwt1.getIssuedAt().getTime(), is(1516239022000L));
        assertThat(jwt1.getNonce(), is("really random text"));

        assertThat(jwt2.getSubject(), is("1234567890"));
        assertThat(jwt2.getIssuedAt().getTime(), is(1516239022000L));
        assertThat(jwt2.getNonce(), is("really random text"));
    }
}