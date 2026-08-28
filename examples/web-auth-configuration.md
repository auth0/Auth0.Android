## Specify audience

```kotlin
WebAuthProvider.login(account)
    .withAudience("https://{YOUR_AUTH0_DOMAIN}/api/v2/")
    .start(this, callback)
```

The sample above requests tokens with the audience required to call the [Management API](https://auth0.com/docs/api/management/v2) endpoints.

> Replace `{YOUR_AUTH0_DOMAIN}` with your actual Auth0 domain (i.e. `mytenant.auth0.com`). If you've set up the tenant to use "Custom Domains", use that value here.

## Specify scope

```kotlin
WebAuthProvider.login(account)
    .withScope("openid profile email read:users")
    .start(this, callback)
```

> The default scope used is `openid profile email`. Regardless of the scopes passed here, the `openid` scope is always enforced.

## Specify Connection scope

```kotlin
WebAuthProvider.login(account)
    .withConnectionScope("email", "profile", "calendar:read")
    .start(this, callback)
```

## Specify Parameter

To [prompt](https://auth0.com/docs/customize/universal-login-pages/customize-login-text-prompts#prompt-values) the user to login or to send custom parameters in the request, `.withParameters` method can be used.

```kotlin
WebAuthProvider.login(account)
    .withParameters(mapOf("prompt" to "login", "custom" to "value"))
    .start(this, callback)
```

## Specify a Custom Authorize URL

In scenarios where you need to use a specific authorize endpoint different from the one derived from your Auth0 domain (e.g., for custom domains, specific tenant configurations), you can provide a full custom URL to the `/authorize` endpoint.

```kotlin
WebAuthProvider
.login(account)
.withAuthorizeUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/authorize")
.start(this, callback)
```

<details>
  <summary>Using Java</summary>

```java
WebAuthProvider
.login(account)
.withAuthorizeUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/authorize")
.start(this, callback);
```
</details>

The URL provided to `.withAuthorizeUrl()` must be a complete and valid HTTPS URL for an OAuth 2.0 authorize endpoint. The SDK will append standard OAuth parameters to this custom base URL.

## Changing the Return To URL scheme
This configuration will probably match what you've done for the [authentication setup](#a-note-about-app-deep-linking).

```kotlin
WebAuthProvider.logout(account)
    .withScheme("myapp")
    .start(this, logoutCallback)
```

## Specify a Custom Logout URL

Similar to the authorize URL, you can specify a custom logout endpoint if your setup requires it (e.g., using custom domains or for specific logout behaviors configured in your Auth0 tenant).

```kotlin
WebAuthProvider
.logout(account)
.withLogoutUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/v2/logout")
.start(this, logoutCallback)
```
<details>
  <summary>Using Java</summary>

```java
WebAuthProvider
.logout(account)
.withLogoutUrl("https://YOUR_CUSTOM_TENANT_OR_AUTH_DOMAIN/v2/logout")
.start(this, logoutCallback);
```
</details>

The URL provided to `.withLogoutUrl()` must be a complete and valid HTTPS URL for logout endpoint. The SDK will append standard logout parameters to this custom base URL.
