### Custom Token Exchange

```kotlin
authentication
    .customTokenExchange("subject_token_type", "subject_token", "organization_id")
    .start(object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
            // Handle success
        }

        override fun onFailure(exception: AuthenticationException) {
            // Handle error
        }

    })
```
<details> 
    <summary>Using coroutines</summary> 

``` kotlin 
try {
    val credentials = authentication
        .customTokenExchange("subject_token_type", "subject_token", "organization_id")
        .await()
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .customTokenExchange("subject_token_type", "subject_token", "organization_id")
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            // Handle success
        }
        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            // Handle error
        }
    });
```


</details>

#### Custom Token Exchange with Actor Token (Delegation/Impersonation)

For delegation or impersonation scenarios where one principal acts on behalf of another (e.g., an AI agent acting on behalf of a user), pass `ActorToken` with the actor token details:

> **Note:** When `actor_token` is present in the request, Auth0 will not issue a refresh token regardless of whether `offline_access` is in the scope. The `Credentials.refreshToken` will be `null` in this flow.

```kotlin
import com.auth0.android.authentication.request.ActorToken

val actorToken = ActorToken(
    token = "actor-token-value",
    tokenType = "urn:my-org:actor-token-type"
)

authentication
    .customTokenExchange(
        subjectTokenType = "http://my-org/custom-token",
        subjectToken = "subject-token-value",
        organization = "org_12345",
        actorToken = actorToken
    )
    .start(object : Callback<Credentials, AuthenticationException> {
        override fun onSuccess(result: Credentials) {
            // Access the actor claim from the ID token
            val actor = result.user.actor
            if (actor != null) {
                println("Actor sub: ${actor.sub}")
                println("Actor properties: ${actor.extraProperties}")
                // Nested delegation chain (if present)
                val nestedActor = actor.actor
            }
        }

        override fun onFailure(exception: AuthenticationException) {
            // Handle error
        }
    })
```

<details>
    <summary>Using coroutines</summary>

```kotlin
try {
    val actorToken = ActorToken(
        token = "actor-token-value",
        tokenType = "urn:my-org:actor-token-type"
    )
    val credentials = authentication
        .customTokenExchange(
            subjectTokenType = "http://my-org/custom-token",
            subjectToken = "subject-token-value",
            actorToken = actorToken
        )
        .await()
    // Access the actor claim
    val actor = credentials.user.actor
} catch (e: AuthenticationException) {
    e.printStackTrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
ActorToken actorToken = new ActorToken(
    "actor-token-value",
    "urn:my-org:actor-token-type"
);

authentication
    .customTokenExchange("http://my-org/custom-token", "subject-token-value", null, actorToken)
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            ActorClaim actor = payload.getUser().getActor();
            if (actor != null) {
                Log.d("CTE", "Actor: " + actor.getSub());
            }
        }
        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            // Handle error
        }
    });
```
</details>
