package com.auth0.android.provider;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.List;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.collection.IsEmptyCollection.empty;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 23, manifest = Config.NONE)
public class PermissionHandlerTest {

    private PermissionHandler handler;

    @Before
    public void setUp() throws Exception {
        handler = new PermissionHandler();
    }

    @Test
    public void shouldHavePermissionGranted() throws Exception {
        final Activity activity = mock(Activity.class);
        when(activity.checkPermission(eq("permission"), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_GRANTED);
        assertTrue(handler.isPermissionGranted(activity, "permission"));
    }

    @Test
    public void shouldHavePermissionDeclined() throws Exception {
        final Activity activity = mock(Activity.class);
        when(activity.checkPermission(eq("permission"), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_DENIED);
        assertFalse(handler.isPermissionGranted(activity, "permission"));
    }

    @Test
    public void shouldHaveAllPermissionsGranted() throws Exception {
        final Activity activity = mock(Activity.class);
        when(activity.checkPermission(anyString(), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_GRANTED);
        assertTrue(handler.areAllPermissionsGranted(activity, new String[]{"permission1", "permission2"}));
    }

    @Test
    public void shouldHaveAllPermissionsDeclined() throws Exception {
        final Activity activity = mock(Activity.class);
        when(activity.checkPermission(anyString(), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_DENIED);
        assertFalse(handler.areAllPermissionsGranted(activity, new String[]{"permission1", "permission2"}));
    }

    @Test
    public void shouldHaveAllPermissionsDeclinedIfOneIsDenied() throws Exception {
        final Activity activity = mock(Activity.class);
        when(activity.checkPermission(eq("permission1"), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_GRANTED);
        when(activity.checkPermission(eq("permission2"), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_DENIED);
        assertFalse(handler.areAllPermissionsGranted(activity, new String[]{"permission1", "permission2"}));
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Test
    public void requestPermissions() throws Exception {
        final Activity activity = mock(Activity.class);
        when(activity.checkPermission(eq("permission1"), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_GRANTED);
        when(activity.checkPermission(eq("permission2"), anyInt(), anyInt())).thenReturn(PackageManager.PERMISSION_DENIED);

        String[] permissions = new String[]{"permission1", "permission2"};
        handler.requestPermissions(activity, permissions, 100);

        verify(activity).requestPermissions(permissions, 100);
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Test
    public void shouldExplainPermissions() throws Exception {
        final Activity activity = mock(Activity.class);
        when(activity.shouldShowRequestPermissionRationale("permission1")).thenReturn(true);
        when(activity.shouldShowRequestPermissionRationale("permission2")).thenReturn(false);

        String[] permissions = new String[]{"permission1", "permission2"};
        final List<String> permissionsToExplain = handler.requestPermissions(activity, permissions, 100);

        assertThat(permissionsToExplain, is(notNullValue()));
        assertThat(permissionsToExplain, hasItem("permission1"));
        assertThat(permissionsToExplain, not(hasItem("permission2")));
    }

    @Test
    public void shouldSetLastRequestCode() throws Exception {
        final Activity activity = mock(Activity.class);
        String[] permissions = new String[]{"permission1", "permission2"};
        handler.requestPermissions(activity, permissions, 100);

        assertThat(handler.getLastRequestCode(), is(100));
    }

    @Test
    public void shouldReturnAllPermissionDeclinedWhenInvalidRequestCode() throws Exception {
        final Activity activity = mock(Activity.class);
        String[] permissions = new String[]{"permission1", "permission2"};
        int[] grantResults = new int[]{PackageManager.PERMISSION_GRANTED, PackageManager.PERMISSION_GRANTED};
        handler.requestPermissions(activity, permissions, 100);

        final List<String> result = handler.parseRequestResult(123, permissions, grantResults);
        assertThat(result, is(notNullValue()));
        assertThat(result, hasItems("permission1", "permission2"));
    }

    @Test
    public void shouldHaveAllPermissionDeclinedByUser() throws Exception {
        final Activity activity = mock(Activity.class);
        handler.requestPermissions(activity, new String[]{}, 100);
        final List<String> result = handler.parseRequestResult(100, new String[]{}, new int[]{});

        assertThat(result, is(notNullValue()));
        assertThat(result, is(empty()));
    }

    @Test
    public void shouldHaveSomePermissionsDeclinedByUser() throws Exception {
        final Activity activity = mock(Activity.class);
        String[] permissions = new String[]{"permission1", "permission2"};
        int[] grantResults = new int[]{PackageManager.PERMISSION_GRANTED, PackageManager.PERMISSION_DENIED};
        handler.requestPermissions(activity, permissions, 100);

        final List<String> result = handler.parseRequestResult(100, permissions, grantResults);
        assertThat(result, is(notNullValue()));
        assertThat(result, hasItems("permission2"));
    }

    @Test
    public void shouldHaveAllPermissionsGrantedByUser() throws Exception {
        final Activity activity = mock(Activity.class);
        String[] permissions = new String[]{"permission1", "permission2"};
        int[] grantResults = new int[]{PackageManager.PERMISSION_GRANTED, PackageManager.PERMISSION_GRANTED};
        handler.requestPermissions(activity, permissions, 100);

        final List<String> result = handler.parseRequestResult(100, permissions, grantResults);
        assertThat(result, is(notNullValue()));
        assertThat(result, is(empty()));
    }

}