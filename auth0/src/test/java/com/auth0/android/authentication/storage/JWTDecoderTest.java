package com.auth0.android.authentication.storage;

import com.auth0.android.jwt.JWT;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(RobolectricTestRunner.class)
public class JWTDecoderTest {

    @Test
    public void shouldDecodeAToken() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        JWT jwt1 = new JWT(token);

        JWT jwt2 = new JWTDecoder().decode(token);

        //Header claims
        assertThat(jwt1.getHeader().get("alg"), is("HS256"));
        assertThat(jwt1.getHeader().get("typ"), is("JWT"));

        assertThat(jwt2.getHeader().get("typ"), is("JWT"));
        assertThat(jwt2.getHeader().get("alg"), is("HS256"));

        //Payload claims
        assertThat(jwt1.getSubject(), is("1234567890"));
        assertThat(jwt1.getIssuedAt().getTime(), is(1516239022000L));
        assertThat(jwt1.getClaim("name").asString(), is("John Doe"));

        assertThat(jwt2.getSubject(), is("1234567890"));
        assertThat(jwt2.getIssuedAt().getTime(), is(1516239022000L));
        assertThat(jwt2.getClaim("name").asString(), is("John Doe"));
    }
}