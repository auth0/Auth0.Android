/*
 * AuthProviderTest.java
 *
 * Copyright (c) 2016 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.auth0.android.provider;

import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.support.annotation.Nullable;
import android.support.v4.content.PermissionChecker;
import android.widget.TextView;

import org.hamcrest.Matcher;
import org.hamcrest.collection.IsMapContaining;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21, manifest = Config.NONE)
public class AuthProviderTest {

    @Mock
    private AuthCallback callback;
    @Mock
    private PermissionHandler handler;
    @Mock
    private Activity activity;
    private AuthProvider provider;
    private boolean processAuthenticationCalled;

    private static final int PERMISSION_REQUEST_CODE = 10;
    private static final int AUTHENTICATION_REQUEST_CODE = 11;
    private static final String[] PROVIDER_PERMISSIONS = new String[]{"PermissionX", "PermissionY"};
    private static final int[] PERMISSIONS_GRANTED = new int[]{PermissionChecker.PERMISSION_GRANTED, PermissionChecker.PERMISSION_GRANTED};

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        processAuthenticationCalled = false;
        provider = new AuthProvider(handler) {

            @Override
            protected void requestAuth(Activity activity, int requestCode) {
                processAuthenticationCalled = true;
            }

            @Override
            public boolean authorize(int requestCode, int resultCode, @Nullable Intent intent) {
                return false;
            }

            @Override
            public String[] getRequiredAndroidPermissions() {
                return PROVIDER_PERMISSIONS;
            }
        };
    }

    @Test
    public void shouldHavePermissionHandler() throws Exception {
        AuthProvider provider = new AuthProvider() {
            @Override
            protected void requestAuth(Activity activity, int requestCode) {
            }

            @Override
            public boolean authorize(int requestCode, int resultCode, @Nullable Intent intent) {
                return false;
            }

            @Override
            public String[] getRequiredAndroidPermissions() {
                return new String[0];
            }
        };

        assertThat(provider.getPermissionHandler(), is(notNullValue()));
        assertThat(provider.getPermissionHandler(), is(instanceOf(PermissionHandler.class)));
    }

    @Test
    public void shouldStop() throws Exception {
        provider.stop();
    }

    @Test
    public void shouldClearSession() throws Exception {
        assertThat(provider.getCallback(), is(nullValue()));
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        assertThat(provider.getCallback(), is(notNullValue()));
        provider.clearSession();
        assertThat(provider.getCallback(), is(nullValue()));
    }

    @Test
    public void shouldCallProcessAuthenticationIfPermissionsWereAlreadyGranted() throws Exception {
        when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        assertThat(processAuthenticationCalled, is(true));
    }

    @Test
    public void shouldCallProcessAuthenticationIfPermissionsAreGranted() throws Exception {
        when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(false);
        when(handler.parseRequestResult(PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED)).thenReturn(Collections.<String>emptyList());
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        provider.onRequestPermissionsResult(activity, PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);

        assertThat(processAuthenticationCalled, is(true));
    }

    @Test
    public void shouldCallCheckPermissionsOnHandler() throws Exception {
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        verify(handler).areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS);
    }

    @Test
    public void shouldCallRequestPermissionsOnHandlerIfPermissionsAreNotAlreadyGranted() throws Exception {
        when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(false);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        verify(handler).requestPermissions(activity, PROVIDER_PERMISSIONS, PERMISSION_REQUEST_CODE);
    }

    @Test
    public void shouldDeliverOnRequestPermissionsResultToHandler() throws Exception {
        provider.onRequestPermissionsResult(activity, PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);

        verify(handler).parseRequestResult(PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);
    }

    @Test
    public void shouldFailWithDialogWhenPermissionsAreNotGranted() throws Exception {
        when(handler.parseRequestResult(PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED)).thenReturn(Arrays.asList("some", "values"));
        Activity activity = Robolectric.buildActivity(Activity.class).create().resume().get();
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        provider.onRequestPermissionsResult(activity, PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);

        ArgumentCaptor<Dialog> dialogCaptor = ArgumentCaptor.forClass(Dialog.class);
        verify(callback).onFailure(dialogCaptor.capture());
        final Dialog dialog = dialogCaptor.getValue();
        assertThat(dialog, is(instanceOf(Dialog.class)));
        assertThat(dialog, is(notNullValue()));
        dialog.show(); //Load the layout
        TextView messageTV = (TextView) dialog.findViewById(android.R.id.message);
        assertThat(messageTV.getText().toString(), containsString("Some permissions required by this provider were not granted. You can try to authenticate again or go to " +
                "the application's permission screen in the phone settings and grant them. The missing permissions are:\n" + "[some, values]"));
    }

    @Test
    public void shouldSetParameters() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("key", "value");
        provider.setParameters(params);

        final Map<String, Object> parameters = provider.getParameters();
        assertThat(parameters, is(notNullValue()));
        assertThat(parameters, hasEntry("key", (Object) "value"));
    }

    @Test
    public void shouldReturnFalseWhenCalledWithIntentByDefault() throws Exception {
        boolean authorizeResult = provider.authorize(new Intent());
        assertFalse(authorizeResult);
    }

    @Test
    public void shouldReturnCallback() throws Exception {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        assertThat(provider.getCallback(), is(callback));
    }

    @Test
    public void shouldReturnNullCallbackIfNotStarted() throws Exception {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);

        assertThat(provider.getCallback(), is(nullValue()));
    }

    @Test
    public void shouldReturnNullCallbackIfSessionCleared() throws Exception {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        provider.clearSession();

        assertThat(provider.getCallback(), is(nullValue()));
    }

}