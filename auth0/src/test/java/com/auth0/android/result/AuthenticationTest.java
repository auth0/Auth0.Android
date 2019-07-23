package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class AuthenticationTest {

    private UserProfile profile;
    private Credentials credentials;

    private Authentication authentication;

    @Before
    public void setUp() {
        credentials = Mockito.mock(Credentials.class);
        profile = Mockito.mock(UserProfile.class);
        authentication = new Authentication(profile, credentials);
    }

    @Test
    public void getProfile() {
        assertThat(authentication.getProfile(), is(profile));
    }

    @Test
    public void getCredentials() {
        assertThat(authentication.getCredentials(), is(credentials));
    }

}