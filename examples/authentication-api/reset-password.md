### Reset a password

Send a password reset email to a database user.

```kotlin
authentication
    .resetPassword("info@auth0.com", "my-database-connection")
    .start(object: Callback<Void?, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(result: Void?) { }
    })
```

If the user belongs to an [organization](../organizations.md#organizations), pass its identifier to associate the reset request with that organization. Auth0 then includes the `organization_id` and `organization_name` values in the password reset redirect URL, and makes them available as variables in customized email templates.

```kotlin
authentication
    .resetPassword("info@auth0.com", "my-database-connection", "org_abc123")
    .start(object: Callback<Void?, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(result: Void?) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    authentication
        .resetPassword("info@auth0.com", "my-database-connection", "org_abc123")
        .await()
    println("Password reset email sent")
} catch (e: AuthenticationException) {
    e.printStackTrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .resetPassword("info@auth0.com", "my-database-connection", "org_abc123")
    .start(new Callback<Void, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Void payload) {
            //Password reset email sent!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The `organization` parameter must be the organization ID (for example, `org_abc123`), not the organization name. It is optional — omit it to send a password reset that is not associated with an organization.
