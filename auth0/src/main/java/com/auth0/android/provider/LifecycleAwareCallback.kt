package com.auth0.android.provider

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback

/**
 * Wraps a user-provided callback and observes the Activity/Fragment lifecycle.
 * When the host is destroyed (e.g. config change), [inner] is set to null so
 * the destroyed Activity is no longer referenced by the SDK.
 *
 * If a result arrives after [inner] has been cleared, the [onDetached] lambda
 * is invoked to cache the result for later recovery via consumePending*Result().
 *
 * @param S the success type (Credentials for login, Void? for logout)
 * @param inner the user's original callback
 * @param lifecycleOwner the Activity or Fragment whose lifecycle to observe
 * @param onDetached called when a result arrives but the callback is already detached
 */
internal class LifecycleAwareCallback<S>(
    @Volatile private var inner: Callback<S, AuthenticationException>?,
    lifecycleOwner: LifecycleOwner,
    private val onDetached: (success: S?, error: AuthenticationException?) -> Unit,
) : Callback<S, AuthenticationException>, DefaultLifecycleObserver {

    init {
        lifecycleOwner.lifecycle.addObserver(this)
    }

    override fun onSuccess(result: S) {
        val cb = inner
        if (cb != null) {
            cb.onSuccess(result)
        } else {
            onDetached(result, null)
        }
    }

    override fun onFailure(error: AuthenticationException) {
        val cb = inner
        if (cb != null) {
            cb.onFailure(error)
        } else {
            onDetached(null, error)
        }
    }

    override fun onDestroy(owner: LifecycleOwner) {
        inner = null
        owner.lifecycle.removeObserver(this)
    }
}
