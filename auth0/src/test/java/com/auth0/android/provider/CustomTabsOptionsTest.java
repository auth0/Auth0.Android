package com.auth0.android.provider;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Parcel;

import androidx.browser.customtabs.CustomTabsIntent;
import androidx.core.content.ContextCompat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class CustomTabsOptionsTest {

    private Activity context;

    @Before
    public void setUp() {
        context = Robolectric.setupActivity(Activity.class);
    }

    @Test
    public void shouldCreateNewBuilder() {
        CustomTabsOptions.Builder builder = CustomTabsOptions.newBuilder();
        assertThat(builder, is(notNullValue()));
    }

    @Test
    public void shouldHaveCompatibleBrowser() {
        PackageManager pm = mock(PackageManager.class);
        BrowserPicker browserPicker = mock(BrowserPicker.class);
        when(browserPicker.getBestBrowserPackage(any(PackageManager.class))).thenReturn("something");

        CustomTabsOptions options = CustomTabsOptions.newBuilder()
                .withBrowserPicker(browserPicker).build();


        assertThat(options.getPreferredPackage(pm), is("something"));
        assertThat(options.hasCompatibleBrowser(pm), is(true));
    }

    @Test
    public void shouldNotHaveCompatibleBrowser() {
        PackageManager pm = mock(PackageManager.class);
        BrowserPicker browserPicker = mock(BrowserPicker.class);
        when(browserPicker.getBestBrowserPackage(any(PackageManager.class))).thenReturn(null);

        CustomTabsOptions options = CustomTabsOptions.newBuilder()
                .withBrowserPicker(browserPicker).build();


        assertThat(options.getPreferredPackage(pm), is(nullValue()));
        assertThat(options.hasCompatibleBrowser(pm), is(false));
    }

    @Test
    public void shouldHaveDefaultValues() {
        CustomTabsOptions options = CustomTabsOptions.newBuilder().build();
        assertThat(options, is(notNullValue()));

        Intent intent = options.toIntent(context, null);

        assertThat(intent, is(notNullValue()));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(false));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0), is(0));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.NO_TITLE));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_SHARE_STATE, CustomTabsIntent.SHARE_STATE_OFF), is(CustomTabsIntent.SHARE_STATE_OFF));

        Parcel parcel = Parcel.obtain();
        options.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        CustomTabsOptions parceledOptions = CustomTabsOptions.CREATOR.createFromParcel(parcel);
        assertThat(parceledOptions, is(notNullValue()));

        Intent parceledIntent = parceledOptions.toIntent(context, null);
        assertThat(parceledIntent, is(notNullValue()));
        assertThat(parceledIntent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(false));
        assertThat(parceledIntent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(parceledIntent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0), is(0));
        assertThat(parceledIntent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.NO_TITLE));
        assertThat(parceledIntent.getIntExtra(CustomTabsIntent.EXTRA_SHARE_STATE, CustomTabsIntent.SHARE_STATE_OFF), is(CustomTabsIntent.SHARE_STATE_OFF));
    }

    @Test
    public void shouldSetShowTitle() {
        CustomTabsOptions options = CustomTabsOptions.newBuilder()
                .showTitle(true)
                .build();
        assertThat(options, is(notNullValue()));

        Intent intent = options.toIntent(context, null);

        assertThat(intent, is(notNullValue()));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.SHOW_PAGE_TITLE));


        Parcel parcel = Parcel.obtain();
        options.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        CustomTabsOptions parceledOptions = CustomTabsOptions.CREATOR.createFromParcel(parcel);
        assertThat(parceledOptions, is(notNullValue()));

        Intent parceledIntent = parceledOptions.toIntent(context, null);
        assertThat(parceledIntent, is(notNullValue()));
        assertThat(parceledIntent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(parceledIntent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.SHOW_PAGE_TITLE));
    }

    @Test
    public void shouldSetToolbarColor() {
        CustomTabsOptions options = CustomTabsOptions.newBuilder()
                .withToolbarColor(android.R.color.black)
                .build();
        assertThat(options, is(notNullValue()));

        Intent intent = options.toIntent(context, null);

        assertThat(intent, is(notNullValue()));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(true));
        int resolvedColor = ContextCompat.getColor(context, android.R.color.black);
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0), is(resolvedColor));


        Parcel parcel = Parcel.obtain();
        options.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        CustomTabsOptions parceledOptions = CustomTabsOptions.CREATOR.createFromParcel(parcel);
        assertThat(parceledOptions, is(notNullValue()));

        Intent parceledIntent = parceledOptions.toIntent(context, null);
        assertThat(parceledIntent, is(notNullValue()));
        assertThat(parceledIntent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(true));
        assertThat(parceledIntent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0), is(resolvedColor));
    }

    @Test
    public void shouldSetBrowserPicker() {
        Activity activity = spy(Robolectric.setupActivity(Activity.class));
        BrowserPickerTest.setupBrowserContext(activity, Collections.singletonList("com.auth0.browser"), null, null);

        BrowserPicker browserPicker = BrowserPicker.newBuilder().build();
        CustomTabsOptions options = CustomTabsOptions.newBuilder()
                .withBrowserPicker(browserPicker)
                .build();
        assertThat(options, is(notNullValue()));

        String preferredPackageBefore = options.getPreferredPackage(activity.getPackageManager());
        assertThat(preferredPackageBefore, is("com.auth0.browser"));

        Parcel parcel = Parcel.obtain();
        options.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        CustomTabsOptions parceledOptions = CustomTabsOptions.CREATOR.createFromParcel(parcel);
        assertThat(parceledOptions, is(notNullValue()));

        String preferredPackageNow = parceledOptions.getPreferredPackage(activity.getPackageManager());
        assertThat(preferredPackageNow, is("com.auth0.browser"));
    }

    @Test
    public void shouldSetDisabledCustomTabPackages() {
        Activity activity = spy(Robolectric.setupActivity(Activity.class));
        BrowserPickerTest.setupBrowserContext(activity, Collections.singletonList("com.auth0.browser"), null, null);
        BrowserPicker browserPicker = BrowserPicker.newBuilder().build();

        CustomTabsOptions options = CustomTabsOptions.newBuilder()
                .withBrowserPicker(browserPicker)
                .withDisabledCustomTabsPackages(List.of("com.auth0.browser"))
                .withToolbarColor(android.R.color.black)
                .build();
        assertThat(options, is(notNullValue()));

        Intent intentNoExtras = options.toIntent(activity, null);

        assertThat(intentNoExtras, is(notNullValue()));
        assertThat(intentNoExtras.getExtras(), is(nullValue()));
        assertEquals(intentNoExtras.getAction(), "android.intent.action.VIEW");

        Parcel parcel = Parcel.obtain();
        options.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        CustomTabsOptions parceledOptions = CustomTabsOptions.CREATOR.createFromParcel(parcel);
        assertThat(parceledOptions, is(notNullValue()));

        Intent parceledIntent = parceledOptions.toIntent(activity, null);
        assertThat(parceledIntent, is(notNullValue()));
        assertThat(parceledIntent.getExtras(), is(nullValue()));
        assertEquals(parceledIntent.getAction(), "android.intent.action.VIEW");

        BrowserPickerTest.setupBrowserContext(activity, Collections.singletonList("com.another.browser"), null, null);
        BrowserPicker browserPicker2 = BrowserPicker.newBuilder().build();

        CustomTabsOptions options2 = CustomTabsOptions.newBuilder()
                .withBrowserPicker(browserPicker2)
                .withDisabledCustomTabsPackages(List.of("com.auth0.browser"))
                .withToolbarColor(android.R.color.black)
                .build();

        Intent intentWithToolbarExtra = options2.toIntent(activity, null);
        assertThat(intentWithToolbarExtra, is(notNullValue()));
        assertThat(intentWithToolbarExtra.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(true));
        int resolvedColor = ContextCompat.getColor(activity, android.R.color.black);
        assertThat(intentWithToolbarExtra.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0), is(resolvedColor));
    }
}