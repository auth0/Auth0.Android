package com.auth0.android.provider;

import com.auth0.android.authentication.AuthenticationException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;


@RunWith(RobolectricTestRunner.class)
public class OAuthManagerTest {

    @Test
    public void shouldHaveValidState() {
        OAuthManager.assertValidState("1234567890", "1234567890");
    }

    @Test
    public void shouldHaveInvalidState() {
        Assert.assertThrows(AuthenticationException.class, () -> OAuthManager.assertValidState("0987654321", "1234567890"));
    }

    @Test
    public void shouldHaveInvalidStateWhenOneIsNull() {
        Assert.assertThrows(AuthenticationException.class, () -> OAuthManager.assertValidState("0987654321", null));
    }
}