package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class UserProfileTest {

    private Date createdAt;
    private List identities;
    private Map extraInfo;
    private Map userMetadata;
    private Map appMetadata;
    private UserProfile userProfile;

    @Before
    public void setUp() {
        createdAt = Mockito.mock(Date.class);
        identities = Mockito.mock(List.class);
        extraInfo = Mockito.mock(Map.class);
        userMetadata = Mockito.mock(Map.class);
        appMetadata = Mockito.mock(Map.class);
        userProfile = new UserProfile("id", "name", "nickname", "pictureUrl", "email", true, "familyName", createdAt, identities, extraInfo, userMetadata, appMetadata, "givenName");
    }

    @Test
    public void getId() {
        assertThat(userProfile.getId(), is("id"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldReturnSubIfMissingId() {
        Map<String, Object> extraInfo = Collections.singletonMap("sub", (Object) "fromSub");
        userProfile = new UserProfile(null, null, null, null, null, false, null, null, null, extraInfo, null, null, null);
        assertThat(userProfile.getId(), is("fromSub"));
    }

    @Test
    public void shouldGetNullIdIfMissing() {
        userProfile = new UserProfile(null, null, null, null, null, false, null, null, null, null, null, null, null);
        assertThat(userProfile.getId(), is(nullValue()));
    }

    @Test
    public void getName() {
        assertThat(userProfile.getName(), is("name"));
    }

    @Test
    public void getNickname() {
        assertThat(userProfile.getNickname(), is("nickname"));
    }

    @Test
    public void getEmail() {
        assertThat(userProfile.getEmail(), is("email"));
    }

    @Test
    public void isEmailVerified() {
        assertThat(userProfile.isEmailVerified(), is(true));
    }

    @Test
    public void getPictureURL() {
        assertThat(userProfile.getPictureURL(), is("pictureUrl"));
    }

    @Test
    public void getCreatedAt() {
        assertThat(userProfile.getCreatedAt(), is(createdAt));
    }

    @Test
    public void getGivenName() {
        assertThat(userProfile.getGivenName(), is("givenName"));
    }

    @Test
    public void getFamilyName() {
        assertThat(userProfile.getFamilyName(), is("familyName"));
    }

    @Test
    public void getUserMetadata() {
        assertThat(userProfile.getUserMetadata(), is(userMetadata));
    }

    @Test
    public void getAppMetadata() {
        assertThat(userProfile.getAppMetadata(), is(appMetadata));
    }

    @Test
    public void getExtraInfo() {
        assertThat(userProfile.getExtraInfo(), is(extraInfo));
    }

    @Test
    public void getIdentities() {
        assertThat(userProfile.getIdentities(), is(identities));
    }

}