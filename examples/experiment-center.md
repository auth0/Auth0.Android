# Experiment Center

[Experiment Center](https://auth0.com/docs/customize/experiment-center/overview) is Auth0's A/B testing platform for authentication flows. It lets you split traffic across variants, measure results, and promote the winner — all inside Auth0.

Pass `experiment_id` and `variation_id` via `withParameters()` to force a user into a specific variation for the login request, bypassing the server-side deterministic assignment. Both IDs are obtained from your Auth0 Dashboard or the Management API.

```kotlin
WebAuthProvider.login(account)
    .withParameters(mapOf(
        "experiment_id" to "<EXPERIMENT_ID>",
        "variation_id" to "<VARIATION_ID>"
    ))
    .start(this, callback)
```

<details>
  <summary>Using coroutines</summary>

```kotlin
WebAuthProvider.login(account)
    .withParameters(mapOf(
        "experiment_id" to "<EXPERIMENT_ID>",
        "variation_id" to "<VARIATION_ID>"
    ))
    .await(this)
```

</details>

<details>
  <summary>Using Java</summary>

```java
WebAuthProvider.login(account)
    .withParameters(new HashMap<String, Object>() {{
        put("experiment_id", "<EXPERIMENT_ID>");
        put("variation_id", "<VARIATION_ID>");
    }})
    .start(this, callback);
```

</details>

When the experiment uses segment targeting, also pass `segment_id`:

```kotlin
WebAuthProvider.login(account)
    .withParameters(mapOf(
        "experiment_id" to "<EXPERIMENT_ID>",
        "variation_id" to "<VARIATION_ID>",
        "segment_id" to "<SEGMENT_ID>"
    ))
    .start(this, callback)
```

<details>
  <summary>Using coroutines</summary>

```kotlin
WebAuthProvider.login(account)
    .withParameters(mapOf(
        "experiment_id" to "<EXPERIMENT_ID>",
        "variation_id" to "<VARIATION_ID>",
        "segment_id" to "<SEGMENT_ID>"
    ))
    .await(this)
```

</details>

<details>
  <summary>Using Java</summary>

```java
WebAuthProvider.login(account)
    .withParameters(new HashMap<String, Object>() {{
        put("experiment_id", "<EXPERIMENT_ID>");
        put("variation_id", "<VARIATION_ID>");
        put("segment_id", "<SEGMENT_ID>");
    }})
    .start(this, callback);
```

</details>

> [!NOTE]
> Experiment Center is an Enterprise feature. The override only applies to the current request — the next login without these parameters reverts to server-side deterministic assignment. Refer to the [Experiment Center documentation](https://auth0.com/docs/customize/experiment-center/overview) for setup instructions.
>
> Only `WebAuthProvider` login reaches Experiment Center. Embedded/native login and ROPG skip `/authorize` entirely and do not support experiment overrides.
