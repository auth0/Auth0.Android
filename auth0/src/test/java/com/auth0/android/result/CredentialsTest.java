package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class CredentialsTest {

    private Credentials credentials;

    @Before
    public void setUp() throws Exception {
        credentials = new Credentials("idToken", "accessToken", "type", "refreshToken", 999999L, "openid profile");
    }

    @Test
    public void getIdToken() throws Exception {
        assertThat(credentials.getIdToken(), is("idToken"));
    }

    @Test
    public void getAccessToken() throws Exception {
        assertThat(credentials.getAccessToken(), is("accessToken"));
    }

    @Test
    public void getType() throws Exception {
        assertThat(credentials.getType(), is("type"));
    }

    @Test
    public void getRefreshToken() throws Exception {
        assertThat(credentials.getRefreshToken(), is("refreshToken"));
    }

    @Test
    public void getExpiresIn() throws Exception {
        assertThat(credentials.getExpiresIn(), is(999999L));
    }

    @Test
    public void getScope() throws Exception {
        assertThat(credentials.getScope(), is("openid profile"));
    }
}