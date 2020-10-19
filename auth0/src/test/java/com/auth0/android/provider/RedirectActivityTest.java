package com.auth0.android.provider;

import android.content.Intent;
import android.net.Uri;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;

import static androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasData;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasFlags;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 18)
public class RedirectActivityTest {


    @Mock
    private Uri uri;

    private RedirectActivity activity;
    private ActivityController<RedirectActivity> activityController;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    private void createActivity(Intent launchIntent) {
        activityController = Robolectric.buildActivity(RedirectActivity.class, launchIntent);
        activity = activityController.get();
    }

    @Test
    public void shouldLaunchAuthenticationActivityWithDataOnSuccess() {
        Intent resultIntent = new Intent();
        resultIntent.setData(uri);

        createActivity(resultIntent);
        activityController.create().start().resume();

        Intent authenticationIntent = shadowOf(activity).getNextStartedActivity();
        assertThat(authenticationIntent, is(notNullValue()));
        assertThat(authenticationIntent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(authenticationIntent, hasData(uri));
        assertThat(authenticationIntent, hasFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP));

        assertThat(activity.isFinishing(), is(true));
        activityController.destroy();
    }

    @Test
    public void shouldLaunchAuthenticationActivityWithoutDataOnCancel() {
        Intent resultIntent = new Intent();
        resultIntent.setData(null);

        createActivity(resultIntent);
        activityController.create().start().resume();

        Intent authenticationIntent = shadowOf(activity).getNextStartedActivity();
        assertThat(authenticationIntent, is(notNullValue()));
        assertThat(authenticationIntent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(authenticationIntent.getData(), is(nullValue()));
        assertThat(authenticationIntent, hasFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP));

        assertThat(activity.isFinishing(), is(true));
        activityController.destroy();
    }
}
