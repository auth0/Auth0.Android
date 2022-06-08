package com.auth0.android.provider;

import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.PermissionChecker;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
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
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        processAuthenticationCalled = false;
        provider = new AuthProvider(handler) {

            @Override
            protected void requestAuth(@NonNull Activity activity, int requestCode) {
                processAuthenticationCalled = true;
            }

            @Override
            public boolean authorize(int requestCode, int resultCode, @Nullable Intent intent) {
                return false;
            }

            @NonNull
            @Override
            public String[] getRequiredAndroidPermissions() {
                return PROVIDER_PERMISSIONS;
            }
        };
    }

    @Test
    public void shouldHavePermissionHandler() {
        AuthProvider provider = new AuthProvider() {
            @Override
            protected void requestAuth(@NonNull Activity activity, int requestCode) {
            }

            @Override
            public boolean authorize(int requestCode, int resultCode, @Nullable Intent intent) {
                return false;
            }

            @NonNull
            @Override
            public String[] getRequiredAndroidPermissions() {
                return new String[0];
            }
        };

        assertThat(provider.getPermissionHandler(), is(notNullValue()));
        assertThat(provider.getPermissionHandler(), is(instanceOf(PermissionHandler.class)));
    }

    @Test
    public void shouldStop() {
        provider.stop();
    }

    @Test
    public void shouldClearSession() {
        assertThat(provider.getCallback(), is(nullValue()));
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        assertThat(provider.getCallback(), is(notNullValue()));
        provider.clearSession();
        assertThat(provider.getCallback(), is(nullValue()));
    }

    @Test
    public void shouldCallProcessAuthenticationIfPermissionsWereAlreadyGranted() {
        when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        assertThat(processAuthenticationCalled, is(true));
    }

    @Test
    public void shouldCallProcessAuthenticationIfPermissionsAreGranted() {
        when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(false);
        when(handler.parseRequestResult(PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED)).thenReturn(Collections.emptyList());
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        provider.onRequestPermissionsResult(activity, PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);

        assertThat(processAuthenticationCalled, is(true));
    }

    @Test
    public void shouldCallCheckPermissionsOnHandler() {
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        verify(handler).areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS);
    }

    @Test
    public void shouldCallRequestPermissionsOnHandlerIfPermissionsAreNotAlreadyGranted() {
        when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(false);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        verify(handler).requestPermissions(activity, PROVIDER_PERMISSIONS, PERMISSION_REQUEST_CODE);
    }

    @Test
    public void shouldDeliverOnRequestPermissionsResultToHandler() {
        provider.onRequestPermissionsResult(activity, PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);

        verify(handler).parseRequestResult(PERMISSION_REQUEST_CODE, PROVIDER_PERMISSIONS, PERMISSIONS_GRANTED);
    }

    @Test
    public void shouldFailWithDialogWhenPermissionsAreNotGranted() {
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
        TextView messageTV = dialog.findViewById(android.R.id.message);
        assertThat(messageTV.getText().toString(), containsString("Some permissions required by this provider were not granted. You can try to authenticate again or go to " +
                "the application's permission screen in the phone settings and grant them. The missing permissions are:\n" + "[some, values]"));
    }

    @Test
    public void shouldSetParameters() {
        Map<String, Object> params = new HashMap<>();
        params.put("key", "value");
        provider.setParameters(params);

        final Map<String, Object> parameters = provider.getParameters();
        assertThat(parameters, is(notNullValue()));
        assertThat(parameters, hasEntry("key", (Object) "value"));
    }

    @Test
    public void shouldReturnFalseWhenCalledWithIntentByDefault() {
        boolean authorizeResult = provider.authorize(new Intent());
        assertFalse(authorizeResult);
    }

    @Test
    public void shouldReturnCallback() {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);

        assertThat(provider.getCallback(), is(callback));
    }

    @Test
    public void shouldReturnNullCallbackIfNotStarted() {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);

        assertThat(provider.getCallback(), is(nullValue()));
    }

    @Test
    public void shouldReturnNullCallbackIfSessionCleared() {
        Mockito.when(handler.areAllPermissionsGranted(activity, PROVIDER_PERMISSIONS)).thenReturn(true);
        provider.start(activity, callback, PERMISSION_REQUEST_CODE, AUTHENTICATION_REQUEST_CODE);
        provider.clearSession();

        assertThat(provider.getCallback(), is(nullValue()));
    }

}