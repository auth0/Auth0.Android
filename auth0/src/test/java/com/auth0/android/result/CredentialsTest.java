package com.auth0.android.result;

import org.hamcrest.CoreMatchers;
import org.junit.Test;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.Is.is;

public class CredentialsTest {

    @Test
    public void shouldCreateWithExpiresAtDateAndSetExpiresIn() {
        Date date = new Date();
        long expiresIn = (date.getTime() - CredentialsMock.CURRENT_TIME_MS) / 1000;
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope");
        assertThat(credentials.getIdToken(), is("idToken"));
        assertThat(credentials.getAccessToken(), is("accessToken"));
        assertThat(credentials.getType(), is("type"));
        assertThat(credentials.getRefreshToken(), is("refreshToken"));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        assertThat(credentials.getExpiresIn().doubleValue(), CoreMatchers.is(closeTo(expiresIn, 1)));
        assertThat(credentials.getExpiresAt(), is(date));
        assertThat(credentials.getScope(), is("scope"));
    }

    @Test
    public void shouldCreateWithExpiresInAndSetExpiresAt() {
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", 86400L);
        assertThat(credentials.getIdToken(), is("idToken"));
        assertThat(credentials.getAccessToken(), is("accessToken"));
        assertThat(credentials.getType(), is("type"));
        assertThat(credentials.getRefreshToken(), is("refreshToken"));
        assertThat(credentials.getExpiresIn(), is(notNullValue()));
        assertThat(credentials.getExpiresIn().doubleValue(), CoreMatchers.is(closeTo(86400, 1)));
        Date expirationDate = new Date(CredentialsMock.CURRENT_TIME_MS + 86400L * 1000);
        assertThat(credentials.getExpiresAt(), is(expirationDate));
    }

    @Test
    public void getScope() {
        Credentials credentials = new Credentials("idToken", "accessToken", "type", "refreshToken", new Date(), "openid profile");
        assertThat(credentials.getScope(), is("openid profile"));
    }
}