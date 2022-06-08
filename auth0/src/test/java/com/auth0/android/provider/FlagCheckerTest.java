package com.auth0.android.provider;

import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Ignore
public class FlagCheckerTest {

    private static final int FLAG_A = 1 << 1;
    private static final int FLAG_B = 1 << 2;

    @Test
    public void shouldHaveFlags() {
        int value = FLAG_A | FLAG_B;
        assertTrue(FlagChecker.hasFlag(value, FLAG_A));
        assertTrue(FlagChecker.hasFlag(value, FLAG_B));
    }

    @Test
    public void shouldNotHaveFlags() {
        int value = 0;
        assertFalse(FlagChecker.hasFlag(value, FLAG_A));
        assertFalse(FlagChecker.hasFlag(value, FLAG_B));
    }

}