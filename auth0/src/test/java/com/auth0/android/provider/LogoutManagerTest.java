package com.auth0.android.provider;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;

import kotlin.Unit;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@RunWith(RobolectricTestRunner.class)
public class LogoutManagerTest {

    @Mock
    Auth0 account;
    @Mock
    VoidCallback callback;
    @Mock
    CustomTabsOptions customTabsOptions;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldCallOnFailureWhenResumedWithCanceledResult() {
        LogoutManager manager = new LogoutManager(account, callback, "https://auth0.com/android/my.app.name/callback", customTabsOptions);
        AuthorizeResult result = mock(AuthorizeResult.class);
        when(result.isCanceled()).thenReturn(true);
        manager.resume(result);
        ArgumentCaptor<Auth0Exception> exceptionCaptor = ArgumentCaptor.forClass(Auth0Exception.class);
        verify(callback).onFailure(exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue().getMessage(), is("The user closed the browser app so the logout was cancelled."));
    }

    @Test
    public void shouldCallOnSuccessWhenResumedWithValidResult() {
        LogoutManager manager = new LogoutManager(account, callback, "https://auth0.com/android/my.app.name/callback", customTabsOptions);
        AuthorizeResult result = mock(AuthorizeResult.class);
        when(result.isCanceled()).thenReturn(false);
        manager.resume(result);
        verify(callback).onSuccess(eq(Unit.INSTANCE));
    }

}