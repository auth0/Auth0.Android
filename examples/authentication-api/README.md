## Authentication API

The client provides methods to authenticate the user against the Auth0 server.

Create a new instance by passing the account:

```kotlin
val authentication = AuthenticationAPIClient(account)
```

<details>
  <summary>Using Java</summary>

```java
AuthenticationAPIClient authentication = new AuthenticationAPIClient(account);
```
</details>

**Note:** If your Auth0 account has the ["Bot Protection"](https://auth0.com/docs/anomaly-detection/bot-protection) feature enabled, your requests might be flagged for verification. Read how to handle this scenario on the [Bot Protection](../bot-protection.md#bot-protection) section.
