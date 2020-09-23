package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class DatabaseUserTest {

    private DatabaseUser databaseUser;

    @Before
    public void setUp() {
        databaseUser = new DatabaseUser("email", "username", true);
    }

    @Test
    public void getEmail() {
        assertThat(databaseUser.getEmail(), is("email"));
    }

    @Test
    public void getUsername() {
        assertThat(databaseUser.getUsername(), is("username"));
    }

    @Test
    public void isEmailVerified() {
        assertThat(databaseUser.isEmailVerified(), is(true));
    }

}