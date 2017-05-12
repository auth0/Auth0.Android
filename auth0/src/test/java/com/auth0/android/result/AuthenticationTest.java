package com.auth0.android.result;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class AuthenticationTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private UserProfile profile;
    private Credentials credentials;
    private Authentication authentication;

    @Before
    public void setUp() throws Exception {
        credentials = Mockito.mock(Credentials.class);
        profile = Mockito.mock(UserProfile.class);
        authentication = new Authentication(profile, credentials);
    }

    @Test
    public void getUserInfo() throws Exception {
        assertThat(authentication.getUserProfile(), is(profile));
    }

    @Test
    public void getCredentials() throws Exception {
        assertThat(authentication.getCredentials(), is(credentials));
    }

    @Test
    public void shouldThrowOnNullInfo() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("profile must be non-null");
        new Authentication(null, credentials);
    }

    @Test
    public void shouldThrowOnNullCredentials() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("credentials must be non-null");
        new Authentication(profile, null);
    }

}