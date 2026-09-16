### Discovery (EA)

> [!IMPORTANT]
> Discovery API is currently in [Early Access](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Please reach out to Auth0 support to get it enabled for your tenant.

The discovery endpoint (`/e/discovery`) reports which grant types a client can use, derived from the client's enabled grants, its enabled connections, and each connection's configured authentication methods.

Discovery is served by the `EmbeddedAuthClient`, which you create from an `Auth0` instance:

```kotlin
val account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN")
val client = EmbeddedAuthClient(account)
```

#### Discover the supported grant types

Call `discover()` to query the tenant. The `connection` argument is optional — omit it to discover everything the application supports, or pass a connection name to scope the result to that connection.

```kotlin
val result = client.discover().await()

if (result.hasEmbeddedAuthorization) {
    // Use embedded authorization flow to login
} else {
    // Use the existing AuthenticationAPI client for login
}
```

To scope discovery to a single connection, pass its name:

```kotlin
val result = client.discover("Username-Password-Authentication").await()
```

#### Inspect the result

`DiscoveryResult` exposes the raw list of `options` alongside convenience accessors that group them by kind, so you can build your UI without inspecting each `LoginOption` yourself:

```kotlin
result.hasEmbeddedAuthorization      // true if embedded authorization support is available
result.types                         // Set<GrantType> of every supported grant
result.passwordRealms                // List<String> of connections that accept password login
result.passkeyConnections            // List<String> of connections that support passkeys
result.otpOptions                    // List<LoginOption.PasswordlessOtp>
result.socialProviders               // List<String> of native social subject-token types
result.options                       // the full List<LoginOption>

// Check for a specific grant type
if (result.supports(GrantType.PASSKEY)) {
    // show the passkey button
}
```

<details>
  <summary>Using callbacks</summary>

```kotlin
client
    .discover()
    .start(object : Callback<DiscoveryResult, EmbeddedAuthException> {
        override fun onFailure(exception: EmbeddedAuthException) { }

        override fun onSuccess(result: DiscoveryResult) {
        }
    })
```
</details>

<details>
  <summary>Using Java</summary>

```java
Auth0 account = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient client = new EmbeddedAuthClient(account);

client
    .discover()
    .start(new Callback<DiscoveryResult, EmbeddedAuthException>() {
        @Override
        public void onSuccess(DiscoveryResult result) {
            //Discovered!
        }

        @Override
        public void onFailure(@NonNull EmbeddedAuthException error) {
            //Error!
        }
    });
```
</details>
