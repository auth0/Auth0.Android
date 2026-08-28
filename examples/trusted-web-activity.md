## Trusted Web Activity

Trusted Web Activity is a feature provided by some browsers to provide a native look and feel to the custom tabs.

To use this feature, there are some additional steps you must take:

- We need the SHA256 fingerprints of the app’s signing certificate. To get this, you can run the following command on your APK
```shell
keytool -printcert -jarfile sample-debug.apk
```
- The fingerprint has to be updated in the [Auth0 Dashboard](https://manage.auth0.com/dashboard/eu/poovamraj/applications) under
Applications > *Specific Application* > Settings > Advanced Settings > Device Settings > Key Hashes
- App's package name has to be entered in the field above

Once the above prerequisites are met, you can call your login method as below to open your web authentication in Trusted Web Activity.

```kotlin
WebAuthProvider.login(account)
    .withTrustedWebActivity()
    .await(this)
```

> [!NOTE]
> `withTrustedWebActivity()` and `withAuthTab()` are mutually exclusive. If both are set on the same builder, TWA takes precedence and Auth Tab will not be used. They rely on different underlying launch mechanisms and cannot be combined. For standard OAuth flows against Auth0, prefer [Auth Tab](#auth-tab-experimental) — it requires no server-side setup and works with any domain.
