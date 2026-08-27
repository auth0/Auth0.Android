## Handling Configuration Changes During Authentication

When the Activity is destroyed during authentication due to a configuration change (e.g. device rotation, locale change, dark mode toggle), the SDK caches the authentication result internally. Call `WebAuthProvider.registerCallbacks()` once in your `onCreate()` to recover it. This single call handles both recovery scenarios:

- **Configuration change**: delivers any cached result on the next `onResume` to the callback
- **Process death**: `AuthenticationActivity` restores OAuth state and processes the redirect. Since static state was wiped, the result is cached and delivered to `loginCallback` on the next `onResume` after `registerCallbacks()` is called

```kotlin
class LoginActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WebAuthProvider.registerCallbacks(
            lifecycleOwner = this,
            loginCallback = object : Callback<Credentials, AuthenticationException> {
                override fun onSuccess(result: Credentials) {
                    // Handle successful login
                }
                override fun onFailure(error: AuthenticationException) {
                    // Handle error
                }
            },
            logoutCallback = object : Callback<Void?, AuthenticationException> {
                override fun onSuccess(result: Void?) {
                    // Handle successful logout
                }
                override fun onFailure(error: AuthenticationException) {
                    // Handle error
                }
            }
        )
    }

    fun onLoginClick() {
        WebAuthProvider.login(account)
            .withScheme("demo")
            .start(this, loginCallback)
    }

    fun onLogoutClick() {
        WebAuthProvider.logout(account)
            .withScheme("demo")
            .start(this, logoutCallback)
    }
}
```

> [!NOTE]
> If you use the `suspend fun await()` API from a ViewModel coroutine scope, the Activity is never captured in the callback chain, so you do not need `registerCallbacks()` calls.
