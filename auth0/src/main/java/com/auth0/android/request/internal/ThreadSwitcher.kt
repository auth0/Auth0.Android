package com.auth0.android.request.internal

import android.os.Handler
import android.os.Looper
import androidx.core.os.HandlerCompat
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Thread Switcher that makes use of the Main Looper
 * and a background thread Executor.
 */
internal object DefaultThreadSwitcher : ThreadSwitcher(
    Looper.getMainLooper(),
    Executors.newFixedThreadPool(MAX_CONCURRENT_THREADS)
)

/**
 * Exposes methods to execute tasks in the background
 * or post tasks in the Main / UI thread.
 * @param mainLooper The Main / UI thread Looper.
 * @param backgroundExecutor The executor that enqueues tasks to be run in the background.
 */
public open class ThreadSwitcher(
    private val mainLooper: Looper,
    private val backgroundExecutor: Executor
) {
    private val mainHandler: Handler by lazy {
        HandlerCompat.createAsync(mainLooper)
    }

    internal companion object {
        /**
         * The maximum concurrent threads to execute
         * in the background. Value taken from the Android docs.
         * @see <a href="https://developer.android.com/guide/background/threading#creating-multiple-threads">Android: creating-multiple-threads</a>
         */
        internal const val MAX_CONCURRENT_THREADS = 4
    }

    /**
     * Posts the task in the Main / UI thread.
     */
    public fun mainThread(runnable: Runnable) {
        mainHandler.post(runnable)
    }

    /**
     * Enqueues the task to be run on a background thread.
     */
    public fun backgroundThread(runnable: Runnable) {
        backgroundExecutor.execute(runnable)
    }
}