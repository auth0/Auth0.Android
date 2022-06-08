package com.auth0.android.result;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

@Ignore
public class UserIdentityTest {

    private Map<String, Object> profileInfo;
    private UserIdentity userIdentity;

    @Before
    public void setUp() {
        profileInfo = Collections.singletonMap("key", "value");
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