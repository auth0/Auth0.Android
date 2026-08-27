## Auth Tab


Auth Tab uses [`AuthTabIntent`](https://developer.android.com/reference/androidx/browser/auth/AuthTabIntent) from `androidx.browser` to open the authentication flow in a dedicated browser tab that verifies the redirect URI scheme before delivering the result back to your app. This provides an additional layer of security by ensuring only your app — whose redirect URI scheme is verified at registration time — can receive the authentication callback, preventing other apps from intercepting it.

Requires `androidx.browser` 1.9.0+ and a browser that supports Auth Tab on the device. On unsupported browsers, the SDK automatically falls back to a regular Custom Tab.

> [!NOTE]
> `withAuthTab()` and `withTrustedWebActivity()` are mutually exclusive. If both are set on the same builder, TWA takes precedence and Auth Tab will not be used. They rely on different underlying launch mechanisms and cannot be combined.

```kotlin
WebAuthProvider.login(account)
    .withAuthTab()
    .start(this, callback)
```

<details>
<summary>Using async/await</summary>

```kotlin
WebAuthProvider.login(account)
    .withAuthTab()
    .await(this)
```
</details>

<details>
  <summary>Using Java</summary>

```java
WebAuthProvider.login(account)
    .withAuthTab()
    .start(this, callback);
```
</details>

Auth Tab can also be used for logout:

```kotlin
WebAuthProvider.logout(account)
    .withAuthTab()
    .start(this, logoutCallback)
```

<details>
  <summary>Using Java</summary>

```java
WebAuthProvider.logout(account)
    .withAuthTab()
    .start(this, logoutCallback);
```
</details>

### Limitations with `CustomTabsOptions`

When `withAuthTab()` is combined with `withCustomTabsOptions()`, only a subset of options take effect. Auth Tab uses a separate intent builder (`AuthTabIntent`) and is always presented full-screen.

| Option | Supported |
|---|---|
| `withToolbarColor()` | ✅ Applied to the Auth Tab toolbar |
| `showTitle()` | ❌ Ignored — Auth Tab has no title-visibility option |
| `withEphemeralBrowsing()` | ❌ Ignored — Auth Tab does not support ephemeral sessions. Use a regular Custom Tab if session isolation is required |
| `withInitialHeight()` / `withInitialWidth()` | ❌ Ignored — Auth Tab is always full-screen |
| `withToolbarCornerRadius()` | ❌ Ignored |
| `withSideSheetBreakpoint()` | ❌ Ignored |
| `withBackgroundInteractionEnabled()` | ❌ Ignored |
