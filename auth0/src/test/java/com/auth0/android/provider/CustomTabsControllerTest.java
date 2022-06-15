package com.auth0.android.provider;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Color;
import android.net.Uri;

import androidx.browser.customtabs.CustomTabsClient;
import androidx.browser.customtabs.CustomTabsIntent;
import androidx.browser.customtabs.CustomTabsServiceConnection;
import androidx.browser.customtabs.CustomTabsSession;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.api.mockito.PowerMockito;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;

import java.util.List;

import static androidx.test.espresso.intent.matcher.IntentMatchers.hasFlag;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
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
public class CustomTabsControllerTest {

    private static final String DEFAULT_BROWSER_PACKAGE = "com.auth0.browser";
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

    private CustomTabsController controller;


    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        Activity activity = Robolectric.setupActivity(Activity.class);
        context = spy(activity);

        //By default, a "compatible" browser is available
        BrowserPicker browserPicker = mock(BrowserPicker.class);
        when(browserPicker.getBestBrowserPackage(context.getPackageManager())).thenReturn(DEFAULT_BROWSER_PACKAGE);
        CustomTabsOptions ctOptions = CustomTabsOptions.newBuilder().withBrowserPicker(browserPicker).build();

        controller = new CustomTabsController(context, ctOptions);
    }

    @Test
    public void shouldUnbind() throws Exception {
        bindService(controller, true);
        connectBoundService();

        controller.unbindService();
        verify(context).unbindService(serviceConnectionCaptor.capture());
        final CustomTabsServiceConnection connection = serviceConnectionCaptor.getValue();
        CustomTabsServiceConnection controllerConnection = controller;
        assertThat(connection, is(equalTo(controllerConnection)));
    }

    @Test
    public void shouldUnbindEvenIfNotBound() throws Exception {
        bindService(controller, false);
        connectBoundService();

        controller.unbindService();
        verify(context).unbindService(any(ServiceConnection.class));
    }

    @Test
    public void shouldBindAndLaunchUri() throws Exception {
        bindService(controller, true);
        controller.launchUri(uri, false);
        connectBoundService();

        verify(context, timeout(MAX_TEST_WAIT_TIME_MS)).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.getPackage(), is(DEFAULT_BROWSER_PACKAGE));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(false));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.NO_TITLE));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_SHARE_STATE, CustomTabsIntent.SHARE_STATE_OFF), is(CustomTabsIntent.SHARE_STATE_OFF));
        assertThat(intent.getData(), is(uri));
        assertThat(intent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
    }

    @Test
    public void shouldLaunchUriUsingFallbackWhenNoCompatibleBrowserIsAvailable() {
        BrowserPicker browserPicker = mock(BrowserPicker.class);
        when(browserPicker.getBestBrowserPackage(context.getPackageManager())).thenReturn(null);
        CustomTabsOptions ctOptions = CustomTabsOptions.newBuilder().withBrowserPicker(browserPicker).build();
        CustomTabsController controller = new CustomTabsController(context, ctOptions);
        controller.launchUri(uri, false);

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
        BrowserPicker browserPicker = mock(BrowserPicker.class);
        when(browserPicker.getBestBrowserPackage(context.getPackageManager())).thenReturn(DEFAULT_BROWSER_PACKAGE);
        CustomTabsOptions ctOptions = CustomTabsOptions.newBuilder()
                .showTitle(true)
                .withToolbarColor(android.R.color.black)
                .withBrowserPicker(browserPicker)
                .build();
        CustomTabsController controller = new CustomTabsController(context, ctOptions);

        bindService(controller, true);
        controller.launchUri(uri, false);
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
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_SHARE_STATE, CustomTabsIntent.SHARE_STATE_OFF), is(CustomTabsIntent.SHARE_STATE_OFF));
        assertThat(intent.getData(), is(uri));
        assertThat(intent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
    }

    @Test
    public void shouldFailToBindButLaunchUri() {
        bindService(controller, false);
        controller.launchUri(uri, false);

        verify(context, timeout(MAX_TEST_WAIT_TIME_MS)).startActivity(launchIntentCaptor.capture());
        Intent intent = launchIntentCaptor.getValue();
        assertThat(intent.getAction(), is(Intent.ACTION_VIEW));
        assertThat(intent.getData(), is(uri));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_SESSION), is(true));
        assertThat(intent, not(hasFlag(Intent.FLAG_ACTIVITY_NO_HISTORY)));
    }

    @Test
    public void shouldNotLaunchUriIfContextNoLongerValid() {
        bindService(controller, true);
        controller.clearContext();
        controller.launchUri(uri, false);
        verify(context, never()).startActivity(any(Intent.class));
    }

    @Test
    public void shouldLaunchUriWithFallbackIfCustomTabIntentFails() {
        doThrow(ActivityNotFoundException.class)
                .doNothing()
                .when(context).startActivity(any(Intent.class));
        controller.launchUri(uri, false);

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
        assertThat(customTabIntent.getIntExtra(CustomTabsIntent.EXTRA_SHARE_STATE, CustomTabsIntent.SHARE_STATE_OFF), is(CustomTabsIntent.SHARE_STATE_OFF));
    }

    //Helper Methods

    @SuppressWarnings("WrongConstant")
    private void bindService(CustomTabsController controller, boolean willSucceed) {
        doReturn(willSucceed).when(context).bindService(
                serviceIntentCaptor.capture(),
                serviceConnectionCaptor.capture(),
                anyInt());
        controller.bindService();
        Intent intent = serviceIntentCaptor.getValue();
        assertThat(intent.getPackage(), is(DEFAULT_BROWSER_PACKAGE));
    }

    private void connectBoundService() throws Exception {
        CustomTabsSession session = mock(CustomTabsSession.class);
        ComponentName componentName = new ComponentName(DEFAULT_BROWSER_PACKAGE, DEFAULT_BROWSER_PACKAGE + ".CustomTabsService");
        //This depends on an implementation detail but is the only way to test it because of methods visibility
        PowerMockito.when(session, "getComponentName").thenReturn(componentName);

        when(customTabsClient.newSession(eq(null))).thenReturn(session);
        CustomTabsServiceConnection conn = serviceConnectionCaptor.getValue();
        conn.onCustomTabsServiceConnected(componentName, customTabsClient);
        verify(customTabsClient).newSession(eq(null));
        verify(customTabsClient).warmup(eq(0L));
    }
}