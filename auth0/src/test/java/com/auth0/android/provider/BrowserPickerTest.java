package com.auth0.android.provider;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Parcel;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.espresso.intent.matcher.IntentMatchers;

import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.hamcrest.MockitoHamcrest;
import org.robolectric.RobolectricTestRunner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.robolectric.Robolectric.setupActivity;

@RunWith(RobolectricTestRunner.class)
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
    // ************************* Parcelable implementation ****************************
    // ********************************************************************************


    @Test
    public void shouldParcelizeAndHaveDefaultValues() {
        BrowserPickerTest.setupBrowserContext(activity, ALL_BROWSERS, null, CHROME_STABLE);
        assertThat(allBrowserPicker, is(notNullValue()));
        String bestPackageBefore = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        assertThat(bestPackageBefore, is(CHROME_STABLE));

        Parcel parcel = Parcel.obtain();
        allBrowserPicker.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        BrowserPicker parceledPicker = BrowserPicker.CREATOR.createFromParcel(parcel);
        assertThat(parceledPicker, is(notNullValue()));

        String bestPackageNow = parceledPicker.getBestBrowserPackage(activity.getPackageManager());
        assertThat(bestPackageNow, is(CHROME_STABLE));
    }

    @Test
    public void shouldParcelizeAndSetAllowedBrowsers() {
        BrowserPickerTest.setupBrowserContext(activity, ALL_BROWSERS, null, CUSTOM_BROWSER_1);
        assertThat(filteredBrowserPicker, is(notNullValue()));
        String bestPackageBefore = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        assertThat(bestPackageBefore, is(CUSTOM_BROWSER_1));

        Parcel parcel = Parcel.obtain();
        filteredBrowserPicker.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        BrowserPicker parceledPicker = BrowserPicker.CREATOR.createFromParcel(parcel);
        assertThat(parceledPicker, is(notNullValue()));

        String bestPackageNow = parceledPicker.getBestBrowserPackage(activity.getPackageManager());
        assertThat(bestPackageNow, is(CUSTOM_BROWSER_1));
    }

    // ********************************************************************************
    // ** Regular non-filtered picker: Asserts we don't change the previous behavior **
    // ********************************************************************************

    @Test
    public void shouldReturnNullBrowserIfNoBrowserAvailable() {
        setupBrowserContext(activity, Collections.emptyList(), null, null);
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
    public void shouldMaintainLegacyBehaviorWithoutDefaultSet() {
        //it will always prefer any browser that is custom tabs compatible.

        //prefer chrome stable when default is not custom tabs compatible
        List<String> currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_STABLE));

        //prefer chrome system when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_SYSTEM));

        //prefer chrome beta when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_BETA));

        //prefer chrome dev when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_DEV));

        //prefer first custom tabs compatible browser when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, null, null);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(currentBrowsers.get(0)));
    }

    @Test
    public void shouldMaintainLegacyBehavior() {
        //it will always prefer a default browser that is custom tabs compatible or any other browser that is custom tabs compatible.

        //prefer default browser over chrome if custom tabs compatible
        List<String> currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        List<String> currentCompatibleBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_1);
        String bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));

        //prefer chrome stable when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_STABLE));

        //prefer chrome system when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_SYSTEM));

        //prefer chrome beta when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CHROME_BETA, CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_BETA));

        //prefer chrome dev when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Arrays.asList(CHROME_DEV, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CHROME_DEV));

        //prefer first custom tabs compatible browser when default is not custom tabs compatible
        currentBrowsers = Arrays.asList(CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        currentCompatibleBrowsers = Collections.singletonList(CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, currentCompatibleBrowsers, CUSTOM_BROWSER_2);
        bestPackage = allBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(currentCompatibleBrowsers.get(0)));
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
    public void whenFilteringShouldNeverPickDefaultBrowserIfRestrictedEvenIfCustomTabsCapable() {
        setupBrowserContext(activity, ALL_BROWSERS, Arrays.asList(CHROME_STABLE, CUSTOM_BROWSER_2), CHROME_STABLE);
        String bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_2));
    }

    @Test
    public void whenFilteringShouldReturnNullIfNoBrowsersAreLeftAfterFiltering() {
        ArrayList<String> installedBrowsers = new ArrayList<>(ALL_BROWSERS);
        installedBrowsers.removeAll(PACKAGES_TO_FILTER_FROM);
        //Next line says the installed browsers are all of those we don't accept
        setupBrowserContext(activity, installedBrowsers, ALL_BROWSERS, null);
        String bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(nullValue()));
    }

    @Test
    public void whenFilteringShouldNeverPickRestrictedBrowsers() {
        //Every test here will pick from the allowed packages that are installed/available
        //allowed packages = CUSTOM_BROWSER_1, CUSTOM_BROWSER_2, CHROME_DEV  (see PACKAGES_TO_FILTER_FROM)

        //picks the first regular browser, ignores default because is restricted
        List<String> currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CHROME_STABLE), CHROME_STABLE);
        String bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(PACKAGES_TO_FILTER_FROM.get(0)));

        //picks the first regular browser, respecting the order of the allowed packages list, and ignoring default because is restricted
        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CHROME_STABLE), CHROME_STABLE);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_2));

        //picks the first custom tab compatible browser, ignoring the default
        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CUSTOM_BROWSER_1), CUSTOM_BROWSER_2);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));

        //picks the default browser, which is also custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CUSTOM_BROWSER_1), CUSTOM_BROWSER_1);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));

        //picks the default browser, which is not custom tabs compatible
        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, null, CUSTOM_BROWSER_1);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));
    }

    @Test
    public void whenFilteringShouldNeverPickRestrictedBrowsersWithoutDefaultSet() {
        //Every test here will pick from the allowed packages that are installed/available
        //allowed packages = CUSTOM_BROWSER_1, CUSTOM_BROWSER_2, CHROME_DEV  (see PACKAGES_TO_FILTER_FROM)

        //picks the first regular browser, ignores default because is not set
        List<String> currentBrowsers = Arrays.asList(CHROME_BETA, CHROME_SYSTEM, CHROME_STABLE, CHROME_DEV, CUSTOM_BROWSER_1, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CHROME_STABLE), null);
        String bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(PACKAGES_TO_FILTER_FROM.get(0)));

        //picks the first regular browser, respecting the order of the allowed packages list, and ignoring default because is not set
        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CHROME_STABLE), null);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_2));

        //picks the first custom tab compatible browser, ignoring the default
        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CUSTOM_BROWSER_1), null);
        bestPackage = filteredBrowserPicker.getBestBrowserPackage(activity.getPackageManager());
        MatcherAssert.assertThat(bestPackage, is(CUSTOM_BROWSER_1));

        //picks the first custom tabs compatible browser
        currentBrowsers = Arrays.asList(CHROME_BETA, CUSTOM_BROWSER_2, CUSTOM_BROWSER_1);
        setupBrowserContext(activity, currentBrowsers, Collections.singletonList(CUSTOM_BROWSER_1), null);
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
        when(pm.resolveActivity(any(Intent.class), eq(PackageManager.MATCH_DEFAULT_ONLY))).thenReturn(defaultPackage);

        List<ResolveInfo> allBrowsers = new ArrayList<>();
        for (String browser : browserPackages) {
            ResolveInfo info = resolveInfoForPackageName(browser);
            if (customTabPackages != null && customTabPackages.contains(browser)) {
                when(pm.resolveService(MockitoHamcrest.argThat(IntentMatchers.hasPackage(browser)), eq(0))).thenReturn(info);
            }
            allBrowsers.add(info);
        }
        when(pm.queryIntentActivities(any(Intent.class), MockitoHamcrest.intThat(isOneOf(0, PackageManager.MATCH_ALL)))).thenReturn(allBrowsers);
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