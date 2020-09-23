package com.auth0.android.provider;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class BrowserPickerTest {


    static void setupBrowserContext(@NonNull Context context, @NonNull String[] customTabEnabledPackages, @Nullable String defaultBrowserPackage) {
        PackageManager pm = mock(PackageManager.class);
        when(context.getPackageManager()).thenReturn(pm);
        ResolveInfo defaultPackage = resolveInfoForPackageName(defaultBrowserPackage);
        when(pm.resolveActivity(any(Intent.class), anyInt())).thenReturn(defaultPackage);

        List<ResolveInfo> customTabsCapable = new ArrayList<>();
        for (String customTabEnabledPackage : customTabEnabledPackages) {
            ResolveInfo info = resolveInfoForPackageName(customTabEnabledPackage);
            when(pm.resolveService(any(Intent.class), eq(0))).thenReturn(info);
            customTabsCapable.add(info);
        }
        when(pm.queryIntentActivities(any(Intent.class), eq(0))).thenReturn(customTabsCapable);
    }

    private static ResolveInfo resolveInfoForPackageName(@Nullable String packageName) {
        if (packageName == null) {
            return null;
        }
        ResolveInfo resInfo = mock(ResolveInfo.class);
        resInfo.activityInfo = new ActivityInfo();
        resInfo.activityInfo.packageName = packageName;
        return resInfo;
    }
}