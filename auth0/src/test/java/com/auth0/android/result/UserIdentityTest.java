package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class UserIdentityTest {

    private Map profileInfo;
    private UserIdentity userIdentity;

    @Before
    public void setUp() {
        profileInfo = Mockito.mock(Map.class);
        userIdentity = new UserIdentity("id", "connection", "provider", true, "accessToken", "accessTokenSecret", profileInfo);
    }

    @Test
    public void getId() {
        assertThat(userIdentity.getId(), is("id"));
    }

    @Test
    public void getConnection() {
        assertThat(userIdentity.getConnection(), is("connection"));
    }

    @Test
    public void getProvider() {
        assertThat(userIdentity.getProvider(), is("provider"));
    }

    @Test
    public void isSocial() {
        assertThat(userIdentity.isSocial(), is(true));
    }

    @Test
    public void getAccessToken() {
        assertThat(userIdentity.getAccessToken(), is("accessToken"));
    }

    @Test
    public void getAccessTokenSecret() {
        assertThat(userIdentity.getAccessTokenSecret(), is("accessTokenSecret"));
    }

    @Test
    public void getProfileInfo() {
        assertThat(userIdentity.getProfileInfo(), is(profileInfo));
    }

}