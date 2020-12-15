package com.auth0.android.authentication.storage;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;

public class ClockImplTest {

    @Test
    public void shouldGetCurrentTime() {
        double time = new ClockImpl().getCurrentTimeMillis();
        assertThat(time, is(closeTo(System.currentTimeMillis(), 1)));
    }
}