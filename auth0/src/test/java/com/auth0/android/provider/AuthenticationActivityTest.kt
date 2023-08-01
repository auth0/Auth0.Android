package com.auth0.android.provider

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Parcelable
import androidx.test.espresso.intent.matcher.IntentMatchers
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.RunnableTask
import com.auth0.android.provider.AuthenticationActivity
import com.auth0.android.provider.CustomTabsOptions
import com.nhaarman.mockitokotlin2.any
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.Is
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.*
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController

@RunWith(RobolectricTestRunner::class)
public class AuthenticationActivityTest {
    @Mock
    private lateinit var uri: Uri

    @Mock
    private lateinit var resultUri: Uri

    @Mock
    private lateinit var customTabsController: CustomTabsController

    @Mock
    private lateinit var customTabsOptions: CustomTabsOptions

    @Captor
    private lateinit var intentCaptor: ArgumentCaptor<Intent>

    @Captor
    private lateinit var uriCaptor: ArgumentCaptor<Uri>

    @Captor
    private lateinit var launchAsTwaCaptor: ArgumentCaptor<Boolean>

    @Captor
    private lateinit var failureCallbackCaptor: ArgumentCaptor<RunnableTask<AuthenticationException>>

    private lateinit var callerActivity: Activity
    private lateinit var activity: AuthenticationActivityMock
    private lateinit var activityController: ActivityController<AuthenticationActivityMock>

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        callerActivity = Mockito.spy(Robolectric.buildActivity(Activity::class.java).get())
    }

    private fun createActivity(configurationIntent: Intent?) {
        activityController = Robolectric.buildActivity(
            AuthenticationActivityMock::class.java, configurationIntent
        )
        activity = activityController.get()
        activity.customTabsController = customTabsController
    }

    @Test
    public fun shouldFinishGracefullyWhenCalledByError() {
        val intent = Intent(callerActivity, AuthenticationActivity::class.java)
        //An invalid call will not pass any expected extras
        createActivity(intent)
        activityController.create().newIntent(intent).start().resume()
        Mockito.verifyNoMoreInteractions(customTabsController)
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(activity.isFinishing, Is.`is`(true))
        activityController.destroy()
    }

    @Test
    public fun shouldAuthenticateUsingBrowser() {
        AuthenticationActivity.authenticateUsingBrowser(
            callerActivity,
            uri,
            false,
            customTabsOptions,
        )
        Mockito.verify(callerActivity).startActivity(intentCaptor.capture())
        createActivity(intentCaptor.value)
        activityController.create().start().resume()
        Mockito.verify(customTabsController).bindService()
        Mockito.verify(customTabsController).launchUri(uriCaptor.capture(), launchAsTwaCaptor.capture(), any(), failureCallbackCaptor.capture())
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(uri))
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(false))
        activityController.pause().stop()
        //Browser is shown
        val authenticationResultIntent = Intent()
        authenticationResultIntent.data = resultUri
        activityController.newIntent(authenticationResultIntent)
        activityController.start().resume()
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(activity.deliveredIntent!!.data, Is.`is`(resultUri))
        MatcherAssert.assertThat(activity.isFinishing, Is.`is`(true))
        activityController.destroy()
        Mockito.verify(customTabsController).unbindService()
    }

    @Test
    public fun shouldAuthenticateUsingBrowserAsTwa() {
        AuthenticationActivity.authenticateUsingBrowser(
            callerActivity,
            uri,
            true,
            customTabsOptions,
        )
        Mockito.verify(callerActivity).startActivity(intentCaptor.capture())
        createActivity(intentCaptor.value)
        activityController.create().start().resume()
        Mockito.verify(customTabsController).bindService()
        Mockito.verify(customTabsController).launchUri(uriCaptor.capture(), launchAsTwaCaptor.capture(), any(), failureCallbackCaptor.capture())
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(uri))
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.nullValue()))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(true))
        activityController.pause().stop()
        //Browser is shown
        val authenticationResultIntent = Intent()
        authenticationResultIntent.data = resultUri
        activityController.newIntent(authenticationResultIntent)
        activityController.start().resume()
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(activity.deliveredIntent!!.data, Is.`is`(resultUri))
        MatcherAssert.assertThat(activity.isFinishing, Is.`is`(true))
        activityController.destroy()
        Mockito.verify(customTabsController).unbindService()
    }

    @Test
    public fun shouldAuthenticateAfterRecreatedUsingBrowser() {
        AuthenticationActivity.authenticateUsingBrowser(
            callerActivity,
            uri,
            false,
            customTabsOptions
        )
        Mockito.verify(callerActivity).startActivity(intentCaptor.capture())
        createActivity(intentCaptor.value)
        activityController.create().start().resume()
        Mockito.verify(customTabsController).bindService()
        Mockito.verify(customTabsController).launchUri(uriCaptor.capture(), launchAsTwaCaptor.capture(), any(), failureCallbackCaptor.capture())
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(uri))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(false))
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.nullValue()))
        //Browser is shown
        //Memory needed. Let's kill the activity
        val authenticationResultIntent = Intent()
        authenticationResultIntent.data = resultUri
        recreateAndCallNewIntent(authenticationResultIntent)
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(activity.deliveredIntent!!.data, Is.`is`(resultUri))
        MatcherAssert.assertThat(activity.isFinishing, Is.`is`(true))
        activityController.destroy()
        Mockito.verify(customTabsController).unbindService()
    }

    @Test
    public fun shouldCancelAuthenticationUsingBrowser() {
        AuthenticationActivity.authenticateUsingBrowser(
            callerActivity,
            uri,
            false,
            customTabsOptions
        )
        Mockito.verify(callerActivity).startActivity(intentCaptor.capture())
        createActivity(intentCaptor.value)
        activityController.create().start().resume()
        Mockito.verify(customTabsController).bindService()
        Mockito.verify(customTabsController).launchUri(uriCaptor.capture(), launchAsTwaCaptor.capture(), any(), failureCallbackCaptor.capture())
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(uriCaptor.value, Is.`is`(uri))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(launchAsTwaCaptor.value, Is.`is`(false))
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.nullValue()))
        activityController.pause().stop()
        //Browser is shown
        activityController.start().resume()
        MatcherAssert.assertThat(activity.deliveredIntent, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            activity.deliveredIntent!!.data,
            Is.`is`(Matchers.nullValue())
        ) //null data == canceled
        MatcherAssert.assertThat(activity.isFinishing, Is.`is`(true))
        activityController.destroy()
        Mockito.verify(customTabsController).unbindService()
    }

    @Test
    public fun shouldLaunchForBrowserAuthentication() {
        AuthenticationActivity.authenticateUsingBrowser(
            callerActivity,
            uri,
            false,
            customTabsOptions
        )
        Mockito.verify(callerActivity).startActivity(intentCaptor.capture())
        val intent = intentCaptor.value
        MatcherAssert.assertThat(intent, Is.`is`(Matchers.notNullValue()))
        MatcherAssert.assertThat(
            intent, IntentMatchers.hasComponent(
                AuthenticationActivity::class.java.name
            )
        )
        MatcherAssert.assertThat(intent, IntentMatchers.hasFlag(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        MatcherAssert.assertThat(intent, CoreMatchers.not(IntentMatchers.hasData(uri)))
        val extras = intent.extras
        MatcherAssert.assertThat(
            extras!!.getParcelable<Parcelable>(AuthenticationActivity.EXTRA_AUTHORIZE_URI) as Uri?,
            Is.`is`(uri)
        )
        MatcherAssert.assertThat(
            extras.getParcelable<Parcelable>(AuthenticationActivity.EXTRA_CT_OPTIONS) as CustomTabsOptions?,
            Is.`is`(customTabsOptions)
        )
    }

    @Test
    public fun shouldCreateCustomTabsController() {
        val authenticationActivity = AuthenticationActivity()
        val ctOptions = CustomTabsOptions.newBuilder().build()
        val controller = authenticationActivity.createCustomTabsController(
            RuntimeEnvironment.application,
            ctOptions
        )
        MatcherAssert.assertThat(controller, Is.`is`(Matchers.notNullValue()))
    }

    private fun recreateAndCallNewIntent(data: Intent) {
        val outState = Bundle()
        activityController.saveInstanceState(outState)
        activityController.pause().stop().destroy()
        createActivity(null)
        activityController.create(outState).start().restoreInstanceState(outState)
        activityController.newIntent(data)
        activityController.resume()
    }
}