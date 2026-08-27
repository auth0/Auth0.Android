## Authenticate with any Auth0 connection

The connection must first be enabled in the Auth0 dashboard for this Auth0 application.

```kotlin
WebAuthProvider.login(account)
    .withConnection("twitter")
    .start(this, callback)
```
