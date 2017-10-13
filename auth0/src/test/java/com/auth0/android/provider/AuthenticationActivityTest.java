package com.auth0.android.provider;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;

import static android.support.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasData;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasFlag;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
@Config(constants = com.auth0.android.auth0.BuildConfig.class, sdk = 18, manifest = Config.NONE)
public class AuthenticationActivityTest {

    @Mock
    private Uri uri;
    @Mock
    private Uri resultUri;
    @Mock
    private CustomTabsController customTabsController;
    @Mock
    private CustomTabsOptions customTabsOptions;
    @Captor
    private ArgumentCaptor<Intent> intentCaptor;
    @Captor
    private ArgumentCaptor<Uri> uriCaptor;

    private Activity callerActivity;
    private AuthenticationActivityMock activity;
    private ShadowActivity activityShadow;
    private ActivityController<AuthenticationActivityMock> activityController;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        callerActivity = spy(Robolectric.buildActivity(Activity.class).get());
    }

    private void createActivity(Intent configurationIntent) {
        activityController = Robolectric.buildActivity(AuthenticationActivityMock.class, configurationIntent);
        activity = activityController.get();
        activity.setCustomTabsController(customTabsController);
        activityShadow = shadowOf(activity);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldAuthenticateUsingBrowser() throws Exception {
        AuthenticationActivity.authenticateUsingBrowser(callerActivity, uri, customTabsOptions);
        verify(callerActivity).startActivity(intentCaptor.capture());

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();

        verify(customTabsController).bindService();
        verify(customTabsController).launchUri(uriCaptor.capture());
        assertThat(uriCaptor.getValue(), is(notNullValue()));
        assertThat(uriCaptor.getValue(), is(uri));
        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        activityController.pause().stop();
        //Browser is shown

        Intent authenticationResultIntent = new Intent();
        authenticationResultIntent.setData(resultUri);
        activityController.newIntent(authenticationResultIntent);
        activityController.start().resume();

        assertThat(activity.getDeliveredIntent(), is(notNullValue()));
        assertThat(activity.getDeliveredIntent().getData(), is(resultUri));

        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
        verify(customTabsController).unbindService();
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldAuthenticateAfterRecreatedUsingBrowser() throws Exception {
        AuthenticationActivity.authenticateUsingBrowser(callerActivity, uri, customTabsOptions);
        verify(callerActivity).startActivity(intentCaptor.capture());

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();

        verify(customTabsController).bindService();
        verify(customTabsController).launchUri(uriCaptor.capture());
        assertThat(uriCaptor.getValue(), is(notNullValue()));
        assertThat(uriCaptor.getValue(), is(uri));
        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        //Browser is shown
        //Memory needed. Let's kill the activity
        Intent authenticationResultIntent = new Intent();
        authenticationResultIntent.setData(resultUri);
        recreateAndCallNewIntent(authenticationResultIntent);

        assertThat(activity.getDeliveredIntent(), is(notNullValue()));
        assertThat(activity.getDeliveredIntent().getData(), is(resultUri));

        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
        verify(customTabsController).unbindService();
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldCancelAuthenticationUsingBrowser() throws Exception {
        AuthenticationActivity.authenticateUsingBrowser(callerActivity, uri, customTabsOptions);
        verify(callerActivity).startActivity(intentCaptor.capture());

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();

        verify(customTabsController).bindService();
        verify(customTabsController).launchUri(uriCaptor.capture());
        assertThat(uriCaptor.getValue(), is(notNullValue()));
        assertThat(uriCaptor.getValue(), is(uri));
        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        activityController.pause().stop();
        //Browser is shown

        activityController.start().resume();

        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
        verify(customTabsController).unbindService();
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldAuthenticateUsingWebView() throws Exception {
        verifyNoMoreInteractions(customTabsController);

        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();
        final ShadowActivity.IntentForResult webViewIntent = activityShadow.getNextStartedActivityForResult();

        Bundle extras = webViewIntent.intent.getExtras();
        assertThat(extras.containsKey(WebAuthActivity.CONNECTION_NAME_EXTRA), is(true));
        assertThat(extras.getString(WebAuthActivity.CONNECTION_NAME_EXTRA), is("facebook"));
        assertThat(extras.containsKey(WebAuthActivity.FULLSCREEN_EXTRA), is(true));
        assertThat(extras.getBoolean(WebAuthActivity.FULLSCREEN_EXTRA), is(true));

        assertThat(webViewIntent.intent, hasComponent(WebAuthActivity.class.getName()));
        assertThat(webViewIntent.intent, hasData(uri));
        assertThat(webViewIntent.requestCode, is(greaterThan(0)));
        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        activityController.pause();
        //WebViewActivity is shown

        Intent authenticationResultIntent = new Intent();
        authenticationResultIntent.setData(resultUri);
        activityShadow.receiveResult(webViewIntent.intent, Activity.RESULT_OK, authenticationResultIntent);

        assertThat(activity.getDeliveredIntent(), is(notNullValue()));
        assertThat(activity.getDeliveredIntent().getData(), is(resultUri));

        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldAuthenticateAfterRecreatedUsingWebView() throws Exception {
        verifyNoMoreInteractions(customTabsController);

        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();
        final ShadowActivity.IntentForResult webViewIntent = activityShadow.getNextStartedActivityForResult();

        Bundle extras = webViewIntent.intent.getExtras();
        assertThat(extras.containsKey(WebAuthActivity.CONNECTION_NAME_EXTRA), is(true));
        assertThat(extras.getString(WebAuthActivity.CONNECTION_NAME_EXTRA), is("facebook"));
        assertThat(extras.containsKey(WebAuthActivity.FULLSCREEN_EXTRA), is(true));
        assertThat(extras.getBoolean(WebAuthActivity.FULLSCREEN_EXTRA), is(true));

        assertThat(webViewIntent.intent, hasComponent(WebAuthActivity.class.getName()));
        assertThat(webViewIntent.intent, hasData(uri));
        assertThat(webViewIntent.requestCode, is(greaterThan(0)));
        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        //WebViewActivity is shown
        //Memory needed. Let's kill the activity
        Intent authenticationResultIntent = new Intent();
        authenticationResultIntent.setData(resultUri);
        recreateAndCallActivityResult(123, authenticationResultIntent);

        assertThat(activity.getDeliveredIntent(), is(notNullValue()));
        assertThat(activity.getDeliveredIntent().getData(), is(resultUri));

        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldCancelAuthenticationUsingWebView() throws Exception {
        verifyNoMoreInteractions(customTabsController);

        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();
        final ShadowActivity.IntentForResult webViewIntent = activityShadow.getNextStartedActivityForResult();

        Bundle extras = webViewIntent.intent.getExtras();
        assertThat(extras.containsKey(WebAuthActivity.CONNECTION_NAME_EXTRA), is(true));
        assertThat(extras.getString(WebAuthActivity.CONNECTION_NAME_EXTRA), is("facebook"));
        assertThat(extras.containsKey(WebAuthActivity.FULLSCREEN_EXTRA), is(true));
        assertThat(extras.getBoolean(WebAuthActivity.FULLSCREEN_EXTRA), is(true));

        assertThat(webViewIntent.intent, hasComponent(WebAuthActivity.class.getName()));
        assertThat(webViewIntent.intent, hasData(uri));
        assertThat(webViewIntent.requestCode, is(greaterThan(0)));
        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        activityController.pause().stop();
        //WebViewActivity is shown

        activityShadow.receiveResult(webViewIntent.intent, Activity.RESULT_CANCELED, null);

        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldLaunchForBrowserAuthentication() throws Exception {
        AuthenticationActivity.authenticateUsingBrowser(callerActivity, uri, customTabsOptions);
        verify(callerActivity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        Assert.assertThat(intent, is(notNullValue()));
        Assert.assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        Assert.assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        Assert.assertThat(intent, not(hasData(uri)));

        Bundle extras = intent.getExtras();
        Assert.assertThat((Uri) extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(uri));
        Assert.assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(false));
        Assert.assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(false));
        Assert.assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        Assert.assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        Assert.assertThat((CustomTabsOptions) extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(customTabsOptions));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldLaunchForWebViewAuthentication() throws Exception {
        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        Intent intent = intentCaptor.getValue();
        Assert.assertThat(intent, is(notNullValue()));
        Assert.assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        Assert.assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        Assert.assertThat(intent, not(hasData(uri)));

        Bundle extras = intentCaptor.getValue().getExtras();
        Assert.assertThat((Uri) extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(uri));
        Assert.assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(true));
        Assert.assertThat(extras.getString(AuthenticationActivity.EXTRA_CONNECTION_NAME), is("facebook"));
        Assert.assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(true));
        Assert.assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(true));
        Assert.assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        Assert.assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(false));
        Assert.assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_CT_OPTIONS), is(false));
    }

    @Test
    public void shouldCreateCustomTabsController() throws Exception {
        final AuthenticationActivity authenticationActivity = new AuthenticationActivity();
        final CustomTabsController controller = authenticationActivity.createCustomTabsController(RuntimeEnvironment.application);

        assertThat(controller, is(notNullValue()));
    }

    private void recreateAndCallNewIntent(Intent data) {
        Bundle outState = new Bundle();
        activityController.saveInstanceState(outState);
        activityController.pause().stop().destroy();
        createActivity(null);
        activityController.create(outState).start().restoreInstanceState(outState);
        activityController.newIntent(data);
        activityController.resume();
    }

    private void recreateAndCallActivityResult(int reqCode, Intent data) {
        Bundle outState = new Bundle();
        activityController.saveInstanceState(outState);
        activityController.pause().stop().destroy();
        createActivity(null);
        activityController.create(outState).start().restoreInstanceState(outState);
        activity.onActivityResult(reqCode, Activity.RESULT_OK, data);
        activityController.resume();
    }
}