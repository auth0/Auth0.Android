package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class AuthenticationTest {

    private UserInfo info;
    private Credentials credentials;

    private Authentication authentication;

    @Before
    public void setUp() throws Exception {
        credentials = Mockito.mock(Credentials.class);
        info = Mockito.mock(UserInfo.class);
        authentication = new Authentication(info, credentials);
    }

    @Test
    public void getUserInfo() throws Exception {
        assertThat(authentication.getUserInfo(), is(info));
    }

    @Test
    public void getCredentials() throws Exception {
        assertThat(authentication.getCredentials(), is(credentials));
    }

}