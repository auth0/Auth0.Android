# Code Style Reference — Auth0.Android

## CI-enforced rules (hard failures)

- **Explicit API mode** (`-Xexplicit-api=strict`): every public declaration needs an explicit visibility modifier AND explicit return type. Compiler rejects implicit visibility.
- **Java 17** source/target (`sourceCompatibility`/`targetCompatibility = VERSION_17`).
- **LF line endings** — `.editorconfig` (`end_of_line = lf`).
- **Android Lint** — `abortOnError = true`; lint errors block the build.

## Naming conventions

| Element | Pattern | Example |
|---------|---------|---------|
| Class / Object | PascalCase | `WebAuthProvider`, `Auth0UserAgent` |
| Exception | `{Domain}Exception` | `AuthenticationException`, `CredentialsManagerException` |
| Function / Method | camelCase | `login()`, `awaitCredentials()` |
| Constant | `UPPER_SNAKE_CASE` | `HEADER_NAME`, `KEY_TOKENS` |
| Enum member | PascalCase | `Factor.OTP` |

## Dual async API (required for Java consumers)

```kotlin
// ✅ Both forms required for every async public method
fun getCredentials(callback: Callback<Credentials, CredentialsManagerException>)
suspend fun awaitCredentials(): Credentials
```

## Explicit visibility (required)

```kotlin
// ✅ Correct
public class Auth0UserAgent public constructor(name: String) {
    public val value: String
}

// ❌ Rejected by -Xexplicit-api=strict
class Auth0UserAgent(name: String) {
    val value: String
}
```

## Typed exceptions — not string matching

```kotlin
// ✅ Correct
catch (e: CredentialsManagerException) {
    when { e.isNoCredentials -> ... }
}

// ❌ Brittle
catch (e: Exception) {
    if (e.message?.contains("no_credentials") == true) { ... }
}
```

## Error hierarchy

`Auth0Exception` → `AuthenticationException` / `CredentialsManagerException` / `DPoPException` / `MyAccountException`

Always throw and catch from this hierarchy; never throw raw `Exception` or `RuntimeException` from public API.
