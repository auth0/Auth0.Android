package com.auth0.android.provider;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;
import com.auth0.android.callback.BaseCallback;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashMap;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@RunWith(RobolectricTestRunner.class)
@Config(sdk = 18)
public class LogoutManagerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Mock
    Auth0 account;
    @Mock
    BaseCallback<Void, Auth0Exception> callback;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldNotHaveCustomTabsOptionsByDefault() throws Exception {
        LogoutManager manager = new LogoutManager(account, callback, new HashMap<String, String>());
        assertThat(manager.customTabsOptions(), is(nullValue()));
    }

    @Test
    public void shouldSetCustomTabsOptions() throws Exception {
        CustomTabsOptions options = mock(CustomTabsOptions.class);
        LogoutManager manager = new LogoutManager(account, callback, new HashMap<String, String>());
        manager.setCustomTabsOptions(options);
        assertThat(manager.customTabsOptions(), is(options));
    }

    @Test
    public void shouldCallOnFailureWhenResumedWithCanceledResult() throws Exception {
        LogoutManager manager = new LogoutManager(account, callback, new HashMap<String, String>());
        AuthorizeResult result = mock(AuthorizeResult.class);
        when(result.isCanceled()).thenReturn(true);
        manager.resume(result);
        ArgumentCaptor<Auth0Exception> exceptionCaptor = ArgumentCaptor.forClass(Auth0Exception.class);
        verify(callback).onFailure(exceptionCaptor.capture());
        assertThat(exceptionCaptor.getValue(), is(notNullValue()));
        assertThat(exceptionCaptor.getValue().getMessage(), is("The user closed the browser app and the log out was cancelled."));
    }

    @Test
    public void shouldCallOnSuccessWhenResumedWithValidResult() throws Exception {
        LogoutManager manager = new LogoutManager(account, callback, new HashMap<String, String>());
        AuthorizeResult result = mock(AuthorizeResult.class);
        when(result.isCanceled()).thenReturn(false);
        manager.resume(result);
        verify(callback).onSuccess(any(Void.class));

    }

}