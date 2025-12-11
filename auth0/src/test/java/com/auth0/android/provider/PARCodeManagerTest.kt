package com.auth0.android.provider

import android.app.Activity
import android.content.Intent
import android.net.Uri
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.provider.WebAuthProvider.par
import com.auth0.android.provider.WebAuthProvider.resume
import com.auth0.android.request.internal.ThreadSwitcherShadow
import com.auth0.android.result.AuthorizationCode
import com.nhaarman.mockitokotlin2.*
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.MockitoAnnotations
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(shadows = [ThreadSwitcherShadow::class])
public class PARCodeManagerTest {

    @Mock
    private lateinit var callback: Callback<AuthorizationCode, AuthenticationException>

    private lateinit var activity: Activity
    private lateinit var account: Auth0

    private val authCodeCaptor: KArgumentCaptor<AuthorizationCode> = argumentCaptor()
    private val authExceptionCaptor: KArgumentCaptor<AuthenticationException> = argumentCaptor()
    private val intentCaptor: KArgumentCaptor<Intent> = argumentCaptor()

    private companion object {
        private const val DOMAIN = "samples.auth0.com"
        private const val CLIENT_ID = "test-client-id"
        private const val REQUEST_URI = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"
        private const val AUTH_CODE = "test-authorization-code"
    }

    @Before
    public fun setUp() {
        MockitoAnnotations.openMocks(this)
        activity = Mockito.spy(Robolectric.buildActivity(Activity::class.java).get())
        account = Auth0.getInstance(CLIENT_ID, DOMAIN)

        // Prevent CustomTabService from being bound to Test environment
        Mockito.doReturn(false).`when`(activity).bindService(
            any(),
            any(),
            ArgumentMatchers.anyInt()
        )
        BrowserPickerTest.setupBrowserContext(
            activity,
            listOf("com.auth0.browser"),
            null,
            null
        )
    }

    @Test
    public fun shouldStartPARFlowWithCorrectAuthorizeUri() {
        par(account)
            .start(activity, REQUEST_URI, callback)

        Assert.assertNotNull(WebAuthProvider.managerInstance)

        verify(activity).startActivity(intentCaptor.capture())
        val uri = intentCaptor.firstValue.getParcelableExtra<Uri>(AuthenticationActivity.EXTRA_AUTHORIZE_URI)
        
        assertThat(uri, `is`(notNullValue()))
        assertThat(uri?.scheme, `is`("https"))
        assertThat(uri?.host, `is`(DOMAIN))
        assertThat(uri?.path, `is`("/authorize"))
        assertThat(uri?.getQueryParameter("client_id"), `is`(CLIENT_ID))
        assertThat(uri?.getQueryParameter("request_uri"), `is`(REQUEST_URI))
    }

    @Test
    public fun shouldResumeWithValidCode() {
        par(account)
            .start(activity, REQUEST_URI, callback)

        verify(activity).startActivity(intentCaptor.capture())
        
        // Create callback intent with code
        val intent = createAuthIntent("code=$AUTH_CODE")
        
        Assert.assertTrue(resume(intent))
        
        verify(callback).onSuccess(authCodeCaptor.capture())
        val authCode = authCodeCaptor.firstValue
        assertThat(authCode, `is`(notNullValue()))
        assertThat(authCode.code, `is`(AUTH_CODE))
    }

    @Test
    public fun shouldFailWithMissingCode() {
        par(account)
            .start(activity, REQUEST_URI, callback)

        verify(activity).startActivity(intentCaptor.capture())
        
        // Create callback intent without code
        val intent = createAuthIntent("foo=bar")
        
        Assert.assertTrue(resume(intent))
        
        verify(callback).onFailure(authExceptionCaptor.capture())
        val exception = authExceptionCaptor.firstValue
        assertThat(exception, `is`(notNullValue()))
        assertThat(exception.isAccessDenied, `is`(true))
    }

    @Test
    public fun shouldFailWithErrorResponse() {
        par(account)
            .start(activity, REQUEST_URI, callback)

        verify(activity).startActivity(intentCaptor.capture())
        
        // Create callback intent with error
        val intent = createAuthIntent("error=access_denied&error_description=User%20denied%20access")
        
        Assert.assertTrue(resume(intent))
        
        verify(callback).onFailure(authExceptionCaptor.capture())
        val exception = authExceptionCaptor.firstValue
        assertThat(exception, `is`(notNullValue()))
        assertThat(exception.getCode(), `is`("access_denied"))
    }

    @Test
    public fun shouldHandleCanceledAuthentication() {
        par(account)
            .start(activity, REQUEST_URI, callback)

        verify(activity).startActivity(intentCaptor.capture())
        
        // Create canceled intent (null data)
        val intent = Intent()
        
        Assert.assertTrue(resume(intent))
        
        verify(callback).onFailure(authExceptionCaptor.capture())
        val exception = authExceptionCaptor.firstValue
        assertThat(exception, `is`(notNullValue()))
        assertThat(exception.isCanceled, `is`(true))
    }

    @Test
    public fun shouldFailWhenNoBrowserAvailable() {
        // Setup context without browser
        BrowserPickerTest.setupBrowserContext(
            activity,
            emptyList(),
            null,
            null
        )

        par(account)
            .start(activity, REQUEST_URI, callback)

        verify(callback).onFailure(authExceptionCaptor.capture())
        val exception = authExceptionCaptor.firstValue
        assertThat(exception, `is`(notNullValue()))
        assertThat(exception.isBrowserAppNotAvailable, `is`(true))
    }

    private fun createAuthIntent(queryString: String): Intent {
        val uri = Uri.parse("https://$DOMAIN/android/com.auth0.test/callback?$queryString")
        return Intent().apply {
            data = uri
        }
    }
}
