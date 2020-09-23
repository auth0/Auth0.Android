package com.auth0.android.provider;

import android.app.Activity;
import android.content.Intent;
import android.os.Parcel;
import android.support.customtabs.CustomTabsIntent;
import android.support.v4.content.ContextCompat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 21)
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
    public void shouldHaveDefaultValues() {
        CustomTabsOptions options = CustomTabsOptions.newBuilder().build();
        assertThat(options, is(notNullValue()));

        Intent intent = options.toIntent(context, null);

        assertThat(intent, is(notNullValue()));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR), is(false));
        assertThat(intent.hasExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE), is(true));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0), is(0));
        assertThat(intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, CustomTabsIntent.NO_TITLE), is(CustomTabsIntent.NO_TITLE));


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
}