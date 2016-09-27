package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class UserProfileTest {

    private Date createdAt;
    private List identities;
    private Map extraInfo;
    private Map userMetadata;
    private Map appMetadata;
    private UserProfile userProfile;

    @Before
    public void setUp() throws Exception {
        createdAt = Mockito.mock(Date.class);
        identities = Mockito.mock(List.class);
        extraInfo = Mockito.mock(Map.class);
        userMetadata = Mockito.mock(Map.class);
        appMetadata = Mockito.mock(Map.class);
        userProfile = new UserProfile("id", "name", "nickname", "pictureUrl", "email", true, "familyName", createdAt, identities, extraInfo, userMetadata, appMetadata, "givenName");
    }

    @Test
    public void getId() throws Exception {
        assertThat(userProfile.getId(), is("id"));
    }

    @Test
    public void getName() throws Exception {
        assertThat(userProfile.getName(), is("name"));
    }

    @Test
    public void getNickname() throws Exception {
        assertThat(userProfile.getNickname(), is("nickname"));
    }

    @Test
    public void getEmail() throws Exception {
        assertThat(userProfile.getEmail(), is("email"));
    }

    @Test
    public void isEmailVerified() throws Exception {
        assertThat(userProfile.isEmailVerified(), is(true));
    }

    @Test
    public void getPictureURL() throws Exception {
        assertThat(userProfile.getPictureURL(), is("pictureUrl"));
    }

    @Test
    public void getCreatedAt() throws Exception {
        assertThat(userProfile.getCreatedAt(), is(createdAt));
    }

    @Test
    public void getGivenName() throws Exception {
        assertThat(userProfile.getGivenName(), is("givenName"));
    }

    @Test
    public void getFamilyName() throws Exception {
        assertThat(userProfile.getFamilyName(), is("familyName"));
    }

    @Test
    public void getUserMetadata() throws Exception {
        assertThat(userProfile.getUserMetadata(), is(userMetadata));
    }

    @Test
    public void getAppMetadata() throws Exception {
        assertThat(userProfile.getAppMetadata(), is(appMetadata));
    }

    @Test
    public void getExtraInfo() throws Exception {
        assertThat(userProfile.getExtraInfo(), is(extraInfo));
    }

    @Test
    public void getIdentities() throws Exception {
        assertThat(userProfile.getIdentities(), is(identities));
    }

}