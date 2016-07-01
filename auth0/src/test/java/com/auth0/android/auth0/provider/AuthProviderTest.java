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

package com.auth0.android.auth0.provider;

import android.app.Activity;
import android.content.Intent;
import android.support.annotation.Nullable;
import android.support.v4.content.PermissionChecker;

import com.auth0.android.auth0.provider.AuthCallback;
import com.auth0.android.auth0.provider.AuthProvider;
import com.auth0.android.auth0.provider.PermissionHandler;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(RobolectricGradleTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
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
    private static final String CONNECTION_NAME = "connectionName";
    private static final String[] PROVIDER_PERMISSIONS = new String[]{"PermissionX", "PermissionY"};
    private static final int[] PERMISSIONS_DENIED = new int[]{PermissionChecker.PERMISSION_DENIED, PermissionChecker.PERMISSION_DENIED};
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
            public void stop() {
            }

            @Override
            public void clearSession() {
            }

            @Override
            public boolean authorize(int requestCode, int resultCode, @Nullable Intent intent) {
                return false;
            }

            @Override
            public boolean authorize(@Nullable Intent intent) {
                return false;
            }

            @Override
            public String[] getRequiredAndroidPermissions() {
                return PROVIDER_PERMISSIONS;
            }
        };
    }

    @Test
    public void shouldCallProcessAuthenticationIfPermissionsWereAlreadyGranted() throws Exception {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        assertThat(processAuthenticationCalled, is(true));
    }

    @Test
    public void shouldCallProcessAuthenticationIfPermissionsAreGranted() throws Exception {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(false);
        Mockito.when(handler.parseRequestResult(PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED)).thenReturn(Collections.<String>emptyList());
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        provider.onRequestPermissionsResult(activity, PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);

        assertThat(processAuthenticationCalled, is(true));
    }

    @Test
    public void shouldCallCheckPermissionsOnHandler() throws Exception {
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        Mockito.verify(handler).areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS);
    }

    @Test
    public void shouldCallRequestPermissionsOnHandlerIfPermissionsAreNotAlreadyGranted() throws Exception {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(false);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        Mockito.verify(handler).requestPermissions(activity, PROVIDER_PERMISSIONS, PERMISSION_REQUEST_CODE);
    }

    @Test
    public void shouldDeliverOnRequestPermissionsResultToHandler() throws Exception {
        provider.onRequestPermissionsResult(activity, PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);

        Mockito.verify(handler).parseRequestResult(PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);
    }
}