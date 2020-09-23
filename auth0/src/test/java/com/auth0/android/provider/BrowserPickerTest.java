package com.auth0.android.provider;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.test.espresso.intent.matcher.IntentMatchers;

import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.robolectric.Robolectric.setupActivity;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 18)
public class BrowserPickerTest {
    private static final String CHROME_STABLE = "com.android.chrome";
    private static final String CHROME_SYSTEM = "com.google.android.apps.chrome";
    private static final String CHROME_BETA = "com.android.chrome.beta";
    private static final String CHROME_DEV = "com.android.chrome.dev";
    private static final String CUSTOM_BROWSER_1 = "com.browser.customtabs1";
    private static final String CUSTOM_BROWSER_2 = "com.browser.customtabs2";
    private static final List<String> ALL_BROWSERS = Arrays.asList(
            CHROME_BETA, CHROME_SYSTEM,
            CHROME_STABLE, CHROME_DEV,
            CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);

    private Activity activity;
    private BrowserPicker allBrowserPicker;
    private BrowserPicker filteredBrowserPicker;
    private static final List<String> PACKAGES_TO_FILTER_FROM = Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2, CHROME_DEV);

    @Before
    public void setUp() {
        activity = spy(setupActivity(Activity.class));
        allBrowserPicker = BrowserPicker.newBuilder().build();
        filteredBrowserPicker = BrowserPicker.newBuilder().withAllowedPackages(PACKAGES_TO_FILTER_FROM).build();
    }

    // ********************************************************************************
    // ** Regular non-filtered picker: Asserts we don't change the previous behavior **
    // ********************************************************************************

    @Test
    public void shouldReturnNullBrowserIfNoBrowserAvailable() {
        setupBrowserContext(activity, Collections.<String>emptyList(), null, null);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(nullValue()));
    }

    @Test
    public void shouldPreferDefaultBrowserIfIsCustomTabsCapable() {
        setupBrowserContext(activity, ALL_BROWSERS, Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2), CUSTOM_BROWSER_1);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));
    }

    @Test
    public void shouldPreferFirstCustomTabsCapableBrowserOverNotCustomTabsCapableDefault() {
        setupBrowserContext(activity, ALL_BROWSERS, Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2), CHROME_DEV);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));
    }

    @Test
    public void shouldPreferDefaultBrowserIfNoneIsCustomTabsCapable() {
        setupBrowserContext(activity, ALL_BROWSERS, null, CHROME_DEV);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_DEV));
    }

    @Test
    public void shouldPreferChromeBrowsersIfDefaultBrowserIsNotSet() {
        List<String> currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_STABLE));

        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_SYSTEM));

        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_BETA));

        currentBrowsers = Arrays.asList(CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_DEV));

        currentBrowsers = Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(currentBrowsers.get(0)));

        currentBrowsers = Collections.singletonList(CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(currentBrowsers.get(0)));
    }

    @Test
    public void shouldMaintainLegacyBehavior() {
        List<String> currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        List<String> currentCompatibleBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_STABLE));

        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_SYSTEM));

        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CHROME_BETA, CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_BETA));

        currentBrowsers = Arrays.asList(CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_DEV));

        currentBrowsers = Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(currentCompatibleBrowsers.get(0)));

        currentBrowsers = Collections.singletonList(CUSTOM_BROWSER_1);
        currentCompatibleBrowsers = Arrays.asList();
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));
    }

    // ********************************************************************************
    // ** Filtered picker: Filters by allowed packages and their order of preference **
    // ** Filtered browser packages: CUSTOM_BROWSER_1, CUSTOM_BROWSER_2, and CHROME_DEV
    // ********************************************************************************

    @Test
    public void whenFilteringShouldPreferFirstCustomTabsCapableBrowserOverNotCustomTabsCapableDefault() {
        setupBrowserContext(activity, ALL_BROWSERS, Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2), CHROME_DEV);
        String bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));
    }

    @Test
    public void whenFilteringShouldPreferDefaultBrowserIfIsCustomTabsCapable() {
        setupBrowserContext(activity, ALL_BROWSERS, Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2), CUSTOM_BROWSER_1);
        String bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));
    }

    @Test
    public void whenFilteringShouldNeverPickRestrictedBrowsers() {
        List<String> currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CHROME_STABLE), CHROME_STABLE);
        String bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(PACKAGES_TO_FILTER_FROM.get(0)));

        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CHROME_STABLE), CHROME_STABLE);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_2));

        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CUSTOM_BROWSER_1), CUSTOM_BROWSER_1);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));
    }


    /**
     * Sets up a given context for using browsers with Custom Tabs.
     * Optionally, supports specifying which of those browsers is set as default by the user.
     */
    static void setupBrowserContext(@NonNull Context context, @NonNull List<String> browserPackages, @Nullable List<String> customTabPackages, @Nullable String defaultBrowserPackage) {
        PackageManager pm = mock(PackageManager.class);
        when(context.getPackageManager()).thenReturn(pm);
        ResolveInfo defaultPackage = resolveInfoForPackageName(defaultBrowserPackage);
        when(pm.resolveActivity(any(Intent.class), anyInt())).thenReturn(defaultPackage);

        List<ResolveInfo> allBrowsers = new ArrayList<>();
        for (String browser : browserPackages) {
            ResolveInfo info = resolveInfoForPackageName(browser);
            if (customTabPackages != null && customTabPackages.contains(browser)) {
                when(pm.resolveService(Matchers.argThat(IntentMatchers.hasPackage(browser)), eq(0))).thenReturn(info);
            }
            allBrowsers.add(info);
        }
        when(pm.queryIntentActivities(any(Intent.class), eq(0))).thenReturn(allBrowsers);
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