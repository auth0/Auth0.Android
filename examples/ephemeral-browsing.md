## Ephemeral Browsing


Ephemeral browsing launches the Chrome Custom Tab in a fully isolated session — cookies, cache, history, and credentials are deleted when the tab closes. This is equivalent to incognito/private mode for Custom Tabs, useful for privacy-focused authentication flows.

Requires Chrome 136+ or a compatible browser. On unsupported browsers, the SDK falls back to a regular Custom Tab and logs a warning.

```kotlin
WebAuthProvider.login(account)
    .withEphemeralBrowsing()
    .start(this, callback)
```

<details>
<summary>Using async/await</summary>

```kotlin
WebAuthProvider.login(account)
    .withEphemeralBrowsing()
    .await(this)
```
</details>

<details>
  <summary>Using Java</summary>

```java
WebAuthProvider.login(account)
    .withEphemeralBrowsing()
    .start(this, callback);
```
</details>
