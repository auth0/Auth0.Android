package com.auth0.android.result;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class DelegationTest {

    private Delegation delegation;

    @Before
    public void setUp() {
        delegation = new Delegation("idToken", "type", 1234567890L);
    }

    @Test
    public void getIdToken() {
        assertThat(delegation.getIdToken(), is("idToken"));
    }

    @Test
    public void getType() {
        assertThat(delegation.getType(), is("type"));
    }

    @Test
    public void getExpiresIn() {
        assertThat(delegation.getExpiresIn(), is(1234567890L));
    }
}