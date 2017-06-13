package com.auth0.android.provider;

import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.support.customtabs.CustomTabsCallback;
import android.support.customtabs.CustomTabsClient;
import android.support.customtabs.CustomTabsIntent;
import android.support.customtabs.CustomTabsServiceConnection;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 21, manifest = Config.NONE)
public class CustomTabsControllerTest {

    private static final String DEFAULT_BROWSER_PACKAGE = "com.auth0.browser";
    private static final String CHROME_STABLE_PACKAGE = "com.android.chrome";
    private static final String CHROME_SYSTEM_PACKAGE = "com.google.android.apps.chrome";
    private static final String CHROME_BETA_PACKAGE = "com.android.chrome.beta";
    private static final String CHROME_DEV_PACKAGE = "com.android.chrome.dev";
    private static final String CUSTOM_TABS_BROWSER_1 = "com.browser.customtabs1";
    private static final String CUSTOM_TABS_BROWSER_2 = "com.browser.customtabs2";

    @Mock
    private Context context;
    @Mock
    private Uri uri;
    @Mock
    private CustomTabsClient customTabsClient;
    @Captor
    private ArgumentCaptor<Intent> launchIntentCaptor;
    @Captor
    private ArgumentCaptor<Intent> serviceIntentCaptor;
    @Captor
    private ArgumentCaptor<CustomTabsServiceConnection> serviceConnectionCaptor;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private CustomTabsController controller;


    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        controller = new CustomTabsController(context, DEFAULT_BROWSER_PACKAGE);
    }

    @Test
    public void shouldChooseNullBrowserIfNoBrowserAvailable() throws Exception {
        preparePackageManagerForCustomTabs(null);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(nullValue()));
    }

    @Test
    public void shouldChooseDefaultBrowserIfIsCustomTabsCapable() throws Exception {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, DEFAULT_BROWSER_PACKAGE);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(DEFAULT_BROWSER_PACKAGE));
    }

    @Test
    public void shouldChooseDefaultBrowserIfNoOtherBrowserIsCustomTabsCapable() throws Exception {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(DEFAULT_BROWSER_PACKAGE));
    }

    @Test
    public void shouldChooseChromeStableOverOtherCustomTabsCapableBrowsers() throws Exception {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_STABLE_PACKAGE, CHROME_SYSTEM_PACKAGE, CHROME_BETA_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(CHROME_STABLE_PACKAGE));
    }

    @Test
    public void shouldChooseChromeSystemOverOtherCustomTabsCapableBrowsers() throws Exception {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_SYSTEM_PACKAGE, CHROME_BETA_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(CHROME_SYSTEM_PACKAGE));
    }

    @Test
    public void shouldChooseChromeBetaOverOtherCustomTabsCapableBrowsers() throws Exception {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_BETA_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(CHROME_BETA_PACKAGE));
    }

    @Test
    public void shouldChooseChromeDevOverOtherCustomTabsCapableBrowsers() throws Exception {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(CHROME_DEV_PACKAGE));
    }

    @Test
    public void shouldChooseCustomTabsCapableBrowserIfAvailable() throws Exception {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestBrowserPackage(context);
        assertThat(bestPackage, is(CUSTOM_TABS_BROWSER_1));
    }

    @Test
    public void shouldUnbind() throws Exception {
        bindService(true, false);
        connectBoundService();

        controller.unbindService();
        verify(context).unbindService(serviceConnectionCaptor.capture());
        final CustomTabsServiceConnection connection = serviceConnectionCaptor.getValue();
        CustomTabsServiceConnection controllerConnection = controller;
        assertThat(connection, is(equalTo(controllerConnection)));
    }

    @SuppressWarnings("WrongConstant")
    @Test
    public void shouldBind() throws Exception {
        boolean success = bindService(true, false);
        assertThat(success, is(true));
        verify(context, never()).startActivity(any(Intent.class));
    }

    @SuppressWarnings("WrongConstant")
    @Test
    public void shouldNotBindIfAlreadyBound() throws Exception {
        bindService(true, false);
        connectBoundService();

        boolean success = bindService(false, false);
        assertThat(success, is(false));
        verify(context, never()).startActivity(any(Intent.class));
    }

    @Test
    public void shouldFailToBind() throws Exception {
        boolean success = bindService(false, false);
        assertThat(success, is(false));
        verify(context, never()).startActivity(any(Intent.class));
    }

    @Test
    public void shouldBindAndLaunchUri() throws Exception {
        boolean success = bindService(true, true);
        assertThat(success, is(true));
        connectBoundService();

        verify(context).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.getData(), is(uri));
        assertThat(intent.getFlags() & Intent.FLAG_ACTIVITY_NO_HISTORY, is(Intent.FLAG_ACTIVITY_NO_HISTORY));
    }

    @Test
    public void shouldFailToBindButLaunchUri() throws Exception {
        boolean success = bindService(false, true);
        assertThat(success, is(false));

        verify(context).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.getData(), is(uri));
        assertThat(intent.getFlags() & Intent.FLAG_ACTIVITY_NO_HISTORY, is(Intent.FLAG_ACTIVITY_NO_HISTORY));
    }

    @Test
    public void shouldLaunchUri() throws Exception {
        controller.launchUri(uri);
        verify(context).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));
        assertThat(intent.getData(), is(uri));
        assertThat(intent.getFlags() & Intent.FLAG_ACTIVITY_NO_HISTORY, is(Intent.FLAG_ACTIVITY_NO_HISTORY));
    }

    @Test
    public void shouldNotLaunchUriIfContextNoLongerValid() throws Exception {
        controller.clearContext();
        controller.launchUri(uri);
        verify(context, never()).startActivity(any(Intent.class));
    }

    @Test
    public void shouldLaunchUriWithFallbackIfCustomTabIntentFails() throws Exception {
        doThrow(ActivityNotFoundException.class)
                .doNothing()
                .when(context).startActivity(any(Intent.class));
        controller.launchUri(uri);
        verify(context, times(2)).startActivity(launchIntentCaptor.capture());
        List<Intent> intents = launchIntentCaptor.getAllValues();

        Intent customTabIntent = intents.get(0);
        assertThat(customTabIntent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(customTabIntent.getData(), is(uri));
        assertThat(customTabIntent.getFlags() & Intent.FLAG_ACTIVITY_NO_HISTORY, is(Intent.FLAG_ACTIVITY_NO_HISTORY));
        assertThat(customTabIntent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));

        Intent fallbackIntent = intents.get(1);
        assertThat(fallbackIntent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(fallbackIntent.getData(), is(uri));
        assertThat(fallbackIntent.getFlags() & Intent.FLAG_ACTIVITY_NO_HISTORY, is(Intent.FLAG_ACTIVITY_NO_HISTORY));
        assertThat(fallbackIntent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(false));
    }

    //Helper Methods

    @SuppressWarnings("WrongConstant")
    private boolean bindService(boolean willSucceed, boolean alsoLaunchUri) {
        Mockito.doReturn(willSucceed).when(context).bindService(
                serviceIntentCaptor.capture(),
                serviceConnectionCaptor.capture(),
                Mockito.anyInt());
        boolean success = alsoLaunchUri ? controller.bindServiceAndLaunchUri(uri) : controller.bindService();
        Intent intent = serviceIntentCaptor.getValue();
        assertThat(intent.getPackage(), is(DEFAULT_BROWSER_PACKAGE));
        return success;
    }

    private void connectBoundService() {
        CustomTabsServiceConnection conn = serviceConnectionCaptor.getValue();
        conn.onCustomTabsServiceConnected(new ComponentName(DEFAULT_BROWSER_PACKAGE, DEFAULT_BROWSER_PACKAGE + ".CustomTabsService"), customTabsClient);
        verify(customTabsClient).newSession(Matchers.<CustomTabsCallback>eq(null));
        verify(customTabsClient).warmup(eq(0L));
    }

    @SuppressWarnings("WrongConstant")
    private void preparePackageManagerForCustomTabs(String defaultBrowserPackage, String... customTabEnabledPackages) {
        PackageManager pm = mock(PackageManager.class);
        when(context.getPackageManager()).thenReturn(pm);
        ResolveInfo defaultPackage = resolveInfoForPackageName(defaultBrowserPackage);
        when(pm.resolveActivity(any(Intent.class), anyInt())).thenReturn(defaultPackage);
        when(pm.resolveService(any(Intent.class), eq(0))).thenReturn(defaultPackage);

        List<ResolveInfo> customTabsCapable = new ArrayList<>();
        for (String customTabEnabledPackage : customTabEnabledPackages) {
            customTabsCapable.add(resolveInfoForPackageName(customTabEnabledPackage));
        }
        when(pm.queryIntentActivities(any(Intent.class), eq(0))).thenReturn(customTabsCapable);
    }

    private ResolveInfo resolveInfoForPackageName(String packageName) {
        if (packageName == null) {
            return null;
        }
        ResolveInfo resInfo = mock(ResolveInfo.class);
        resInfo.activityInfo = new ActivityInfo();
        resInfo.activityInfo.packageName = packageName;
        return resInfo;
    }
}