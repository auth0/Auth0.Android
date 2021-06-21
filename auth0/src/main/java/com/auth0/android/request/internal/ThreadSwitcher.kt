package com.auth0.android.request.internal

import android.os.Handler
import android.os.Looper
import androidx.annotation.VisibleForTesting
import androidx.core.os.HandlerCompat
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * The maximum concurrent threads to execute
 * in the background. Value taken from the Android docs.
 * @see <a href="https://developer.android.com/guide/background/threading#creating-multiple-threads">Android: creating-multiple-threads</a>
 */
private const val MAX_CONCURRENT_THREADS = 4

/**
 * Thread Switcher that makes use of the Main Looper
 * and a background thread Executor.
 * @param backgroundExecutor The executor that enqueues tasks to be run in the background.
 */
internal class DefaultThreadSwitcher(
    private val backgroundExecutor: Executor = Executors.newFixedThreadPool(MAX_CONCURRENT_THREADS)
) : ThreadSwitcher {

    @Volatile
    private var mainHandler: Handler? = null

    override fun mainThread(runnable: Runnable) {
        mainHandler ?: synchronized(this) {
            if (mainHandler == null) {
                mainHandler = createAsync(Looper.getMainLooper())
            }
        }
        mainHandler?.post(runnable)
    }

    override fun backgroundThread(runnable: Runnable) {
        backgroundExecutor.execute(runnable)
    }

    private fun createAsync(looper: Looper): Handler {
        return HandlerCompat.createAsync(looper)
    }
}

/**
 * Common implementation for classes that exposes methods to execute tasks in the background
 * or post tasks in the Main / UI thread.
 */
public interface ThreadSwitcher {
    /**
     * Posts the task in the Main / UI thread.
     */
    public fun mainThread(runnable: Runnable)

    /**
     * Enqueues the task to be run on a background thread.
     */
    public fun backgroundThread(runnable: Runnable)
}

/**
 *  Implementation of [ThreadSwitcher] that allows users to set their own task executor,
 *  aside from the Looper-based DefaultThreadSwitcher that it uses as default for task execution.
 */
public class CommonThreadSwitcher(
    private val defaultThreadSwitcher: ThreadSwitcher
) : ThreadSwitcher {
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal var delegateThreadSwitcher: ThreadSwitcher

    /**
     * Set a delegate thread switcher instead of the DefaultThreadSwitcher,
     * should you wish to have your own object that handles task execution.
     * If set to `null`, the default Looper-based [DefaultThreadSwitcher] will be used.
     * This is useful for unit tests when you don't want to use the actual main looper.
     */
    public fun setDelegate(threadSwitcher: ThreadSwitcher?) {
        delegateThreadSwitcher = threadSwitcher ?: defaultThreadSwitcher
    }

    override fun mainThread(runnable: Runnable) {
        delegateThreadSwitcher.mainThread(runnable)
    }

    override fun backgroundThread(runnable: Runnable) {
        delegateThreadSwitcher.backgroundThread(runnable)
    }

    public companion object {
        @Volatile
        private var INSTANCE: CommonThreadSwitcher? = null

        @JvmStatic
        public fun getInstance(): CommonThreadSwitcher {
            if (INSTANCE != null) {
                return INSTANCE!!
            }
            synchronized(this) {
                if (INSTANCE == null) {
                    INSTANCE = CommonThreadSwitcher(DefaultThreadSwitcher())
                }
            }
            return INSTANCE!!
        }
    }

    init {
        delegateThreadSwitcher = defaultThreadSwitcher
    }

}
