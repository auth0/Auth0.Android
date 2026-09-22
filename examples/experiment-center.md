# Experiment Center

[Experiment Center](https://auth0.com/docs/customize/experiment-center/overview) is Auth0's A/B testing platform for authentication flows. It lets you split traffic across variants, measure results, and promote the winner — all inside Auth0.

Pass `experiment_id`, `variation_id`, and optionally `segment_id` via `withParameters()` to force a user into a specific variation for the login request, bypassing the server-side deterministic assignment. All three IDs are obtained from your Auth0 Dashboard or the Management API:

- `experiment_id` — the ID of the experiment to target
- `variation_id` — the specific variation to assign to this user
- `segment_id` — _(optional)_ restricts the override to a particular audience segment within the experiment

```kotlin
WebAuthProvider.login(account)
    .withParameters(mapOf(
        "experiment_id" to "<EXPERIMENT_ID>",
        "variation_id" to "<VARIATION_ID>",
        "segment_id" to "<SEGMENT_ID>"       // optional
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
        "segment_id" to "<SEGMENT_ID>"       // optional
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
        put("segment_id", "<SEGMENT_ID>");   // optional
    }})
    .start(this, callback);
```

</details>

> [!NOTE]
> Experiment Center is currently in Beta and runs only on **development tenants**. Production tenants are not supported during the Beta period. The override only applies to the current request — the next login without these parameters reverts to server-side deterministic assignment. Refer to the [Experiment Center documentation](https://auth0.com/docs/customize/experiment-center/overview) for setup instructions.
>
> Only `WebAuthProvider` login reaches Experiment Center. Embedded/native login and ROPG skip `/authorize` entirely and do not support experiment overrides.
