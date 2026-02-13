package com.auth0.android.request.internal;

import org.robolectric.android.util.concurrent.InlineExecutorService;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;

/**
 * Shadow that makes use of the {@link InlineExecutorService} to run background threads
 * as soon as they are posted (synchronously). Used only when classes or methods
 * are annotated with @Config(shadows = CommonThreadSwitcher.class)
 *
 * @see <a href="https://github.com/robolectric/robolectric/issues/5645#issuecomment-627512678">https://github.com/robolectric/robolectric/issues/5645#issuecomment-627512678</a>
 * @see <a href="http://robolectric.org/javadoc/4.3/org/robolectric/android/util/concurrent/RoboExecutorService.html">http://robolectric.org/javadoc/4.3/org/robolectric/android/util/concurrent/RoboExecutorService.html</a>
 */
@Implements(CommonThreadSwitcher.class)
@SuppressWarnings({"unused", "RedundantSuppression"})
public class ThreadSwitcherShadow {

    private final InlineExecutorService executor;

    public ThreadSwitcherShadow() {
        this.executor = new InlineExecutorService();
    }

    @Implementation
    public void backgroundThread(Runnable runnable) {
        executor.execute(runnable);
    }

    @Implementation
    public void mainThread(Runnable runnable) {
        executor.execute(runnable);
    }
}
