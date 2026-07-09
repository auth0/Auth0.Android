package com.auth0.android.provider

import android.app.Activity
import android.net.Uri
import androidx.browser.auth.AuthTabIntent
import com.auth0.android.authentication.AuthenticationException
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import org.mockito.Mockito.mock

public class AuthTabResultHandlerTest {

    @Test
    public fun shouldCallOnSuccessWithUriOnResultOk() {
        val uri = mock(Uri::class.java)
        var deliveredUri: Uri? = null
        val handler = AuthTabResultHandler(
            onSuccess = { deliveredUri = it },
            onFailure = { fail("unexpected failure") },
            onCancel = { fail("unexpected cancel") }
        )

        handler.handle(Activity.RESULT_OK, uri)

        assertThat(deliveredUri, `is`(uri))
    }

    @Test
    public fun shouldCallOnSuccessWithNullUriWhenResultOkHasNoUri() {
        var deliveredUri: Uri? = mock(Uri::class.java)
        val handler = AuthTabResultHandler(
            onSuccess = { deliveredUri = it },
            onFailure = { fail("unexpected failure") },
            onCancel = { fail("unexpected cancel") }
        )

        handler.handle(Activity.RESULT_OK, null)

        assertNull(deliveredUri)
    }

    @Test
    public fun shouldCallOnCancelOnResultCanceled() {
        var cancelCalled = false
        val handler = AuthTabResultHandler(
            onSuccess = { fail("unexpected success") },
            onFailure = { fail("unexpected failure") },
            onCancel = { cancelCalled = true }
        )

        handler.handle(Activity.RESULT_CANCELED, null)

        assertThat(cancelCalled, `is`(true))
    }

    @Test
    public fun shouldCallOnFailureOnResultVerificationFailed() {
        var error: AuthenticationException? = null
        val handler = AuthTabResultHandler(
            onSuccess = { fail("unexpected success") },
            onFailure = { error = it },
            onCancel = { fail("unexpected cancel") }
        )

        handler.handle(AuthTabIntent.RESULT_VERIFICATION_FAILED, null)

        assertThat(error?.getCode(), `is`("a0.auth_tab_verification_failed"))
    }

    @Test
    public fun shouldCallOnFailureOnResultVerificationTimedOut() {
        var error: AuthenticationException? = null
        val handler = AuthTabResultHandler(
            onSuccess = { fail("unexpected success") },
            onFailure = { error = it },
            onCancel = { fail("unexpected cancel") }
        )

        handler.handle(AuthTabIntent.RESULT_VERIFICATION_TIMED_OUT, null)

        assertThat(error?.getCode(), `is`("a0.auth_tab_verification_failed"))
    }

    @Test
    public fun shouldCallOnCancelOnUnknownResultCode() {
        var cancelCalled = false
        val handler = AuthTabResultHandler(
            onSuccess = { fail("unexpected success") },
            onFailure = { fail("unexpected failure") },
            onCancel = { cancelCalled = true }
        )

        handler.handle(AuthTabIntent.RESULT_UNKNOWN_CODE, null)

        assertThat(cancelCalled, `is`(true))
    }
}
