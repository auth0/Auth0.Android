package com.auth0.android.util

import com.auth0.android.request.internal.CommonThreadSwitcher
import com.auth0.android.request.internal.ThreadSwitcher
import org.junit.rules.TestWatcher
import org.junit.runner.Description

/**
 * A JUnit4 Rule that replaces the default executor used by [CommonThreadSwitcher] with a
 * different one which executes each task synchronously. Can be used in unit tests instead of
 * Robolectric's Shadows so that `Method getMainLooper in android.os.Looper not mocked` errors are not encountered.
 */
public class CommonThreadSwitcherRule : TestWatcher() {
    override fun starting(description: Description) {
        super.starting(description)
        CommonThreadSwitcher.getInstance().setDelegate(object : ThreadSwitcher {
            override fun mainThread(runnable: Runnable) {
                runnable.run()
            }

            override fun backgroundThread(runnable: Runnable) {
                runnable.run()
            }
        })
    }

    override fun finished(description: Description) {
        super.finished(description)
        CommonThreadSwitcher.getInstance().setDelegate(null)
    }
}
