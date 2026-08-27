## Unit testing with JUnit 4 or JUnit 5

### Handling `Method getMainLooper in android.os.Looper not mocked` errors
Your unit tests might break with `Caused by: java.lang.RuntimeException: Method getMainLooper in android.os.Looper not mocked` due to the Looper being used internally by this library. There are two options to handle this:
1. Use Robolectric Shadows - see this [test](https://github.com/auth0/Auth0.Android/blob/main/auth0/src/test/java/com/auth0/android/authentication/AuthenticationAPIClientTest.kt#L44-L45) for an example
2. If your project does not use Robolectric and uses JUnit 4, you can create a `Rule` that you can add to your unit test:
```kotlin
import com.auth0.android.request.internal.CommonThreadSwitcher
import com.auth0.android.request.internal.ThreadSwitcher
import org.junit.rules.TestWatcher
import org.junit.runner.Description

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
```
See this [test](https://github.com/auth0/Auth0.Android/blob/main/auth0/src/test/java/com/auth0/android/request/internal/CommonThreadSwitcherDelegateTest.kt) for an example of it being used.

3. If you use JUnit 5 then you can create an `Extension` similar to the previous `Rule` for JUnit 4:
```kotlin
import com.auth0.android.request.internal.CommonThreadSwitcher
import com.auth0.android.request.internal.ThreadSwitcher
import org.junit.jupiter.api.extension.AfterEachCallback
import org.junit.jupiter.api.extension.BeforeEachCallback
import org.junit.jupiter.api.extension.ExtensionContext

class CommonThreadSwitcherExtension : BeforeEachCallback, AfterEachCallback {

    override fun beforeEach(context: ExtensionContext?) {
        CommonThreadSwitcher.getInstance().setDelegate(object : ThreadSwitcher {
            override fun mainThread(runnable: Runnable) {
                runnable.run()
            }

            override fun backgroundThread(runnable: Runnable) {
                runnable.run()
            }
        })
    }

    override fun afterEach(context: ExtensionContext?) {
        CommonThreadSwitcher.getInstance().setDelegate(null)
    }

}
```

### Handling SSL errors
You might encounter errors similar to `PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target`, which means that you need to set up your unit tests in a way that ignores or trusts all SSL certificates. In that case, you may have to implement your own `NetworkingClient` so that you can supply your own `SSLSocketFactory` and `X509TrustManager`, and use that in creating your `Auth0` object. See the [`DefaultClient`](https://github.com/auth0/Auth0.Android/blob/main/auth0/src/main/java/com/auth0/android/request/DefaultClient.kt) class for an idea on how to extend `NetworkingClient`.
