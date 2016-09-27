package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class DatabaseUserTest {

    private DatabaseUser databaseUser;

    @Before
    public void setUp() throws Exception {
        databaseUser = new DatabaseUser("email", "username", true);
    }

    @Test
    public void getEmail() throws Exception {
        assertThat(databaseUser.getEmail(), is("email"));
    }

    @Test
    public void getUsername() throws Exception {
        assertThat(databaseUser.getUsername(), is("username"));
    }

    @Test
    public void isEmailVerified() throws Exception {
        assertThat(databaseUser.isEmailVerified(), is(true));
    }

}