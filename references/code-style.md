# Code Style Reference — Auth0.Android

## Enforced by CI (lint / compiler)

These rules fail the build — treat them as hard guardrails:

- **Explicit API mode** (`-Xexplicit-api=strict`): every public declaration must have an explicit visibility modifier AND an explicit return type. The compiler rejects implicit visibility.
- **Kotlin JVM target 11**: do not use APIs that require JVM 12+.
- **LF line endings**: enforced by `.editorconfig` (`end_of_line = lf`).
- **Android Lint**: `abortOnError = true` — lint errors block the build.

## Naming Conventions

| Element | Pattern | Example |
|---------|---------|---------|
| Package | `com.auth0.android.{domain}` | `com.auth0.android.authentication` |
| Class / Object | PascalCase | `Auth0.kt`, `WebAuthProvider.kt` |
| Exception | `{Domain}Exception` | `AuthenticationException`, `CredentialsManagerException` |
| Interface | PascalCase | `Callback<T, E>`, `SenderConstraining` |
| Function / Method | camelCase | `login()`, `saveCredentials()` |
| Property | camelCase; private backing fields with `_` prefix when needed | `clientId`, `_innerState` |
| Constant | `UPPER_SNAKE_CASE` | `HEADER_NAME`, `KEY_TOKENS` |
| Enum member | PascalCase | `Factor.OTP`, `Factor.SMS` |

## Dominant Patterns

**Builder / fluent configuration (WebAuthProvider):**

```kotlin
// ✅ Good — builder chaining, explicit return types, explicit visibility
WebAuthProvider.login(account)
    .withScope("openid profile email")
    .withAudience("https://api.example.com")
    .start(activity, callback)
```

**Dual async API (callback + suspend):**

```kotlin
// ✅ Good — both paths required for Java + Kotlin consumers
// Callback form:
credentialsManager.getCredentials(object : Callback<Credentials, CredentialsManagerException> {
    override fun onSuccess(result: Credentials) { /* ... */ }
    override fun onFailure(error: CredentialsManagerException) { /* ... */ }
})

// Suspend form:
val credentials: Credentials = credentialsManager.awaitCredentials()
```

**Typed exceptions (not string matching):**

```kotlin
// ✅ Good
catch (e: CredentialsManagerException) {
    when {
        e.isNoCredentials -> handleMissing()
        e.isExpired -> handleExpiry()
        else -> handleUnknown(e)
    }
}

// ❌ Bad — brittle, breaks on server-side message changes
catch (e: Exception) {
    if (e.message?.contains("no_credentials") == true) { ... }
}
```

**Explicit visibility (required):**

```kotlin
// ✅ Good
public class Auth0UserAgent public constructor(name: String) {
    public val value: String
    public fun encode(): String = ...
}

// ❌ Bad — implicit visibility, rejected by -Xexplicit-api=strict
class Auth0UserAgent(name: String) {
    val value: String
    fun encode(): String = ...
}
```

**Error hierarchy:**

`Auth0Exception` → `AuthenticationException` / `CredentialsManagerException` / `DPoPException` / `ManagementException` / `MyAccountException`

Always throw and catch from this hierarchy; never throw raw `Exception` or `RuntimeException` from public API.

## Java Interoperability

Public SDK APIs must be callable from Java. Key implications:
- Suspend functions need a `@JvmStatic` callback equivalent OR explicit use of `Coroutines.await()` helpers.
- Default parameters on public functions need `@JvmOverloads` when Java callers need them.
- Kotlin-only idioms (sealed classes, extension functions on internals) are fine internally, but the public API surface must be Java-callable.
- Test Java callability by checking at least one Java test per new public entry point.
