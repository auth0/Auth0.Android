package com.auth0.android.result;

import org.junit.Test;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class CredentialsTest {

    @Test
    public void shouldCreate() {
        Date date = new Date();
        Credentials credentials = new CredentialsMock("idToken", "accessToken", "type", "refreshToken", date, "scope");
        assertThat(credentials.getIdToken(), is("idToken"));
        assertThat(credentials.getAccessToken(), is("accessToken"));
        assertThat(credentials.getType(), is("type"));
        assertThat(credentials.getRefreshToken(), is("refreshToken"));
        assertThat(credentials.getExpiresAt(), is(date));
        assertThat(credentials.getScope(), is("scope"));
    }

    @Test
    public void getScope() {
        Credentials credentials = new Credentials("idToken", "accessToken", "type", "refreshToken", new Date(), "openid profile");
        assertThat(credentials.getScope(), is("openid profile"));
    }
}