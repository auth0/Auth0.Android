package com.auth0.android.provider;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Color;
import android.net.Uri;
import android.support.customtabs.CustomTabsCallback;
import android.support.customtabs.CustomTabsClient;
import android.support.customtabs.CustomTabsIntent;
import android.support.customtabs.CustomTabsServiceConnection;
import android.support.customtabs.CustomTabsSession;

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
import org.powermock.api.mockito.PowerMockito;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayList;
import java.util.List;

import static android.support.test.espresso.intent.matcher.IntentMatchers.hasFlag;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
public class CustomTabsControllerTest {

    private static final String DEFAULT_BROWSER_PACKAGE = "com.auth0.browser";
    private static final String CHROME_STABLE_PACKAGE = "com.android.chrome";
    private static final String CHROME_SYSTEM_PACKAGE = "com.google.android.apps.chrome";
    private static final String CHROME_BETA_PACKAGE = "com.android.chrome.beta";
    private static final String CHROME_DEV_PACKAGE = "com.android.chrome.dev";
    private static final String CUSTOM_TABS_BROWSER_1 = "com.browser.customtabs1";
    private static final String CUSTOM_TABS_BROWSER_2 = "com.browser.customtabs2";
    private static final long MAX_TEST_WAIT_TIME_MS = 2000;

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
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        Activity activity = Robolectric.setupActivity(Activity.class);
        context = spy(activity);
        //By using this constructor, the "default browser" is Custom Tabs compatible
        controller = new CustomTabsController(context, DEFAULT_BROWSER_PACKAGE);
    }

    @Test
    public void shouldNotHaveCustomizationOptionsSetByDefault() {
        CustomTabsController controller = new CustomTabsController(context, DEFAULT_BROWSER_PACKAGE);
        assertThat(controller.getCustomizationOptions(), is(nullValue()));
    }

    @Test
    public void shouldChangeCustomizationOptions() {
        CustomTabsOptions options = mock(CustomTabsOptions.class);
        CustomTabsController controller = new CustomTabsController(context, DEFAULT_BROWSER_PACKAGE);
        controller.setCustomizationOptions(options);
        assertThat(controller.getCustomizationOptions(), is(options));
    }

    @Test
    public void shouldChooseNullBrowserIfNoBrowserAvailable() {
        preparePackageManagerForCustomTabs(null);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(nullValue()));
    }

    @Test
    public void shouldChooseDefaultBrowserIfIsCustomTabsCapable() {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, DEFAULT_BROWSER_PACKAGE);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(DEFAULT_BROWSER_PACKAGE));
    }

    @Test
    public void shouldReturnNullIfNoBrowserIsCustomTabsCapable() {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(nullValue()));
    }

    @Test
    public void shouldChooseChromeStableOverOtherCustomTabsCapableBrowsers() {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_STABLE_PACKAGE, CHROME_SYSTEM_PACKAGE, CHROME_BETA_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(CHROME_STABLE_PACKAGE));
    }

    @Test
    public void shouldChooseChromeSystemOverOtherCustomTabsCapableBrowsers() {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_SYSTEM_PACKAGE, CHROME_BETA_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(CHROME_SYSTEM_PACKAGE));
    }

    @Test
    public void shouldChooseChromeBetaOverOtherCustomTabsCapableBrowsers() {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_BETA_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(CHROME_BETA_PACKAGE));
    }

    @Test
    public void shouldChooseChromeDevOverOtherCustomTabsCapableBrowsers() {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CHROME_DEV_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(CHROME_DEV_PACKAGE));
    }

    @Test
    public void shouldChooseCustomTabsCapableBrowserIfAvailable() {
        preparePackageManagerForCustomTabs(DEFAULT_BROWSER_PACKAGE, CUSTOM_TABS_BROWSER_1, CUSTOM_TABS_BROWSER_2);
        String bestPackage = CustomTabsController.getBestSupportedBrowserPackage(context,  null);
        assertThat(bestPackage, is(CUSTOM_TABS_BROWSER_1));
    }

    @Test
    public void shouldUnbind() throws Exception {
        bindService(true);
        connectBoundService();

        controller.unbindService();
        verify(context).unbindService(serviceConnectionCaptor.capture());
        final CustomTabsServiceConnection connection = serviceConnectionCaptor.getValue();
        CustomTabsServiceConnection controllerConnection = controller;
        assertThat(connection, is(equalTo(controllerConnection)));
    }

    @Test
    public void shouldNotUnbindIfNotBound() throws Exception {
        bindService(false);
        connectBoundService();

        controller.unbindService();
        verify(context, never()).unbindService(any(ServiceConnection.class));
    }

    @Test
    public void shouldBindAndLaunchUri() throws Exception {
        bindService(true);
        controller.launchUri(uri);
        connectBoundService();

        verify(context, timeout(MAX_TEST_WAIT_TIME_MS)).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.getPackage(), is(DEFAULT_BROWSER_PACKAGE));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(false));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.NO_TITLE));
        assertThat(intent.getData(), is(uri));
        assertThat(intent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
    }

    @Test
    public void shouldLaunchUriUsingFallbackWhenNoCustomTabsCompatibleBrowserIsAvailable() {
        CustomTabsController controller = new CustomTabsController(context, (String[]) null);
        controller.launchUri(uri);

        verify(context, timeout(MAX_TEST_WAIT_TIME_MS)).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        //A null package name would make the OS decide the best app to resolve the intent
        assertThat(intent.getPackage(), is(nullValue()));
        assertThat(intent.getData(), is(uri));
        assertThat(intent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
    }

    @Test
    public void shouldBindAndLaunchUriWithCustomization() throws Exception {
        CustomTabsOptions options = CustomTabsOptions.newBuilder()
                .showTitle(true)
                .withToolbarColor(android.R.color.black)
                .build();

        bindService(true);
        controller.setCustomizationOptions(options);
        controller.launchUri(uri);
        connectBoundService();

        verify(context, timeout(MAX_TEST_WAIT_TIME_MS)).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.getPackage(), is(DEFAULT_BROWSER_PACKAGE));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(true));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.SHOW_PAGE_TITLE));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0), is(Color.BLACK));
        assertThat(intent.getData(), is(uri));
        assertThat(intent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
    }

    @Test
    public void shouldFailToBindButLaunchUri() {
        bindService(false);
        controller.launchUri(uri);

        verify(context, timeout(MAX_TEST_WAIT_TIME_MS)).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.getData(), is(uri));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));
        assertThat(intent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
    }

    @Test
    public void shouldNotLaunchUriIfContextNoLongerValid() {
        bindService(true);
        controller.clearContext();
        controller.launchUri(uri);
        verify(context, never()).startActivity(any(Intent.class));
    }

    @Test
    public void shouldLaunchUriWithFallbackIfCustomTabIntentFails() {
        doThrow(ActivityNotFoundException.class)
                .doNothing()
                .when(context).startActivity(any(Intent.class));
        controller.launchUri(uri);

        verify(context, timeout(MAX_TEST_WAIT_TIME_MS)).startActivity(launchIntentCaptor.capture());
        List<Intent> intents = launchIntentCaptor.getAllValues();

        Intent customTabIntent = intents.get(0);
        assertThat(customTabIntent.getAction(), is(Intent.ACTION_VIEW));
        //A null package name would make the OS decide the best app to resolve the intent
        assertThat(customTabIntent.getPackage(), is(nullValue()));
        assertThat(customTabIntent.getData(), is(uri));
        assertThat(customTabIntent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
        assertThat(customTabIntent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));
        assertThat(customTabIntent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(customTabIntent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(false));
        assertThat(customTabIntent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.NO_TITLE));
    }

    //Helper Methods

    @SuppressWarnings("WrongConstant")
    private void bindService(boolean willSucceed) {
        doReturn(willSucceed).when(context).bindService(
                serviceIntentCaptor.capture(),
                serviceConnectionCaptor.capture(),
                Mockito.anyInt());
        controller.bindService();
        Intent intent = serviceIntentCaptor.getValue();
        assertThat(intent.getPackage(), is(DEFAULT_BROWSER_PACKAGE));
    }

    private void connectBoundService() throws Exception {
        CustomTabsSession session = mock(CustomTabsSession.class);
        ComponentName componentName = new ComponentName(DEFAULT_BROWSER_PACKAGE, DEFAULT_BROWSER_PACKAGE + ".CustomTabsService");
        //This depends on an implementation detail but is the only way to test it because of methods visibility
        PowerMockito.when(session, "getComponentName").thenReturn(componentName);

        when(customTabsClient.newSession(Matchers.<CustomTabsCallback>eq(null))).thenReturn(session);
        CustomTabsServiceConnection conn = serviceConnectionCaptor.getValue();
        conn.onCustomTabsServiceConnected(componentName, customTabsClient);
        verify(customTabsClient).newSession(Matchers.<CustomTabsCallback>eq(null));
        verify(customTabsClient).warmup(eq(0L));
    }

    @SuppressWarnings("WrongConstant")
    private void preparePackageManagerForCustomTabs(String defaultBrowserPackage, String... customTabEnabledPackages) {
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