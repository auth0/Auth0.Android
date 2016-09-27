package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Map;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class UserIdentityTest {

    private Map profileInfo;
    private UserIdentity userIdentity;

    @Before
    public void setUp() throws Exception {
        profileInfo = Mockito.mock(Map.class);
        userIdentity = new UserIdentity("id", "connection", "provider", true, "accessToken", "accessTokenSecret", profileInfo);
    }

    @Test
    public void getId() throws Exception {
        assertThat(userIdentity.getId(), is("id"));
    }

    @Test
    public void getConnection() throws Exception {
        assertThat(userIdentity.getConnection(), is("connection"));
    }

    @Test
    public void getProvider() throws Exception {
        assertThat(userIdentity.getProvider(), is("provider"));
    }

    @Test
    public void isSocial() throws Exception {
        assertThat(userIdentity.isSocial(), is(true));
    }

    @Test
    public void getAccessToken() throws Exception {
        assertThat(userIdentity.getAccessToken(), is("accessToken"));
    }

    @Test
    public void getAccessTokenSecret() throws Exception {
        assertThat(userIdentity.getAccessTokenSecret(), is("accessTokenSecret"));
    }

    @Test
    public void getProfileInfo() throws Exception {
        assertThat(userIdentity.getProfileInfo(), is(profileInfo));
    }

}