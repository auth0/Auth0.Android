package com.auth0.android.provider;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

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

import static androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasData;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasFlag;
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
@Config(sdk = 18)
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
    private ActivityController<AuthenticationActivityMock> activityController;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        callerActivity = spy(Robolectric.buildActivity(Activity.class).get());
    }

    private void createActivity(Intent configurationIntent) {
        activityController = Robolectric.buildActivity(AuthenticationActivityMock.class, configurationIntent);
        activity = activityController.get();
        activity.setCustomTabsController(customTabsController);
    }

    @Test
    public void shouldFinishGracefullyWhenCalledByError() {
        Intent intent = new Intent(callerActivity, AuthenticationActivity.class);
        //An invalid call will not pass any expected extras
        createActivity(intent);

        activityController.create().newIntent(intent).start().resume();

        verifyNoMoreInteractions(customTabsController);
        assertThat(activity.getDeliveredIntent(), is(nullValue()));
        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
    }

    @Test
    public void shouldAuthenticateUsingBrowser() {
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

    @Test
    public void shouldAuthenticateAfterRecreatedUsingBrowser() {
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

    @Test
    public void shouldCancelAuthenticationUsingBrowser() {
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

        assertThat(activity.getDeliveredIntent(), is(notNullValue()));
        assertThat(activity.getDeliveredIntent().getData(), is(nullValue())); //null data == canceled
        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
        verify(customTabsController).unbindService();
    }

    @Test
    public void shouldAuthenticateUsingWebView() {
        verifyNoMoreInteractions(customTabsController);

        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();
        final ShadowActivity.IntentForResult webViewIntent = shadowOf(activity).getNextStartedActivityForResult();

        Bundle extras = webViewIntent.intent.getExtras();
        assert extras != null;
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
        shadowOf(activity).receiveResult(webViewIntent.intent, Activity.RESULT_OK, authenticationResultIntent);

        assertThat(activity.getDeliveredIntent(), is(notNullValue()));
        assertThat(activity.getDeliveredIntent().getData(), is(resultUri));

        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
    }

    @Test
    public void shouldAuthenticateAfterRecreatedUsingWebView() {
        verifyNoMoreInteractions(customTabsController);

        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();
        final ShadowActivity.IntentForResult webViewIntent = shadowOf(activity).getNextStartedActivityForResult();

        Bundle extras = webViewIntent.intent.getExtras();
        assert extras != null;
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

    @Test
    public void shouldCancelAuthenticationUsingWebView() {
        verifyNoMoreInteractions(customTabsController);

        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        createActivity(intentCaptor.getValue());
        activityController.create().start().resume();
        final ShadowActivity.IntentForResult webViewIntent = shadowOf(activity).getNextStartedActivityForResult();

        Bundle extras = webViewIntent.intent.getExtras();
        assert extras != null;
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

        shadowOf(activity).receiveResult(webViewIntent.intent, Activity.RESULT_CANCELED, null);
        activityController.resume();

        assertThat(activity.getDeliveredIntent(), is(notNullValue()));
        assertThat(activity.getDeliveredIntent().getData(), is(nullValue()));
        assertThat(activity.isFinishing(), is(true));

        activityController.destroy();
    }

    @Test
    public void shouldLaunchForBrowserAuthentication() {
        AuthenticationActivity.authenticateUsingBrowser(callerActivity, uri, customTabsOptions);
        verify(callerActivity).startActivity(intentCaptor.capture());

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent, not(hasData(uri)));

        Bundle extras = intent.getExtras();
        assert extras != null;
        assertThat((Uri) extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(uri));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(false));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat((CustomTabsOptions) extras.getParcelable(AuthenticationActivity.EXTRA_CT_OPTIONS), is(customTabsOptions));
    }

    @Test
    public void shouldLaunchForWebViewAuthentication() {
        AuthenticationActivity.authenticateUsingWebView(callerActivity, uri, 123, "facebook", true);
        verify(callerActivity).startActivityForResult(intentCaptor.capture(), eq(123));

        Intent intent = intentCaptor.getValue();
        assertThat(intent, is(notNullValue()));
        assertThat(intent, hasComponent(AuthenticationActivity.class.getName()));
        assertThat(intent, hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        assertThat(intent, not(hasData(uri)));

        Bundle extras = intentCaptor.getValue().getExtras();
        assert extras != null;
        assertThat((Uri) extras.getParcelable(AuthenticationActivity.EXTRA_AUTHORIZE_URI), is(uri));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_CONNECTION_NAME), is(true));
        assertThat(extras.getString(AuthenticationActivity.EXTRA_CONNECTION_NAME), is("facebook"));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_FULL_SCREEN), is(true));
        assertThat(extras.containsKey(AuthenticationActivity.EXTRA_USE_BROWSER), is(true));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_USE_BROWSER), is(false));
        assertThat(extras.getBoolean(AuthenticationActivity.EXTRA_CT_OPTIONS), is(false));
    }

    @Test
    public void shouldCreateCustomTabsController() {
        final AuthenticationActivity authenticationActivity = new AuthenticationActivity();
        CustomTabsOptions ctOptions = CustomTabsOptions.newBuilder().build();
        //noinspection deprecation
        final CustomTabsController controller = authenticationActivity.createCustomTabsController(RuntimeEnvironment.application, ctOptions);

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
        if (!activity.isFinishing()) {
            activityController.resume();
        }
    }
}
