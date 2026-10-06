# Push Notification Polling (OOB)

Push MFA is the one factor that needs a loop. **The SDK never polls** — `verifyOob()`
performs exactly one poll per call, and the app owns the loop.

The pattern is always the same:

1. `challengePush()` sends the notification and continues with a `NextAction.VerifyOob`
   carrying `pollInMs` — how long to wait before the first poll.
2. Wait that long, then call `verifyOob()`.
3. Each `verifyOob()` either:
   - **succeeds** → the push was approved; you get `Credentials`.
   - **continues** with `AUTHORIZATION_PENDING` or `SLOW_DOWN` and a fresh
     `VerifyOob(pollInMs)` → wait the new delay and poll again.
   - **fails terminally** (`AuthorizationRejected`, `ChallengeExpired`, `SessionExpired`)
     → stop.

Both pending states arrive as `EmbeddedAuthError.InsufficientAuthorization` carrying a new
`VerifyOob` delay, so one helper covers them: it returns the next delay to wait, or `null`
when the outcome is terminal.

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

// Next poll delay from a pending-push continuation, or null when the push is terminal.
// The server always includes poll_in_ms on a pending VerifyOob.
private fun EmbeddedAuthException.nextPushDelayMs(): Long? =
    (error as? EmbeddedAuthError.InsufficientAuthorization)
        ?.nextActions?.filterIsInstance<NextAction.VerifyOob>()
        ?.firstOrNull()?.pollInMs?.toLong()

// Assumes the flow has already reached the push factor (see authorize.md / identify).
suspend fun verifyPush(): Credentials {
    // challengePush always continues with a VerifyOob carrying the first poll delay.
    var delayMs = try {
        embedded.challengePush().await()
        error("challengePush always continues")
    } catch (e: EmbeddedAuthException) {
        e.nextPushDelayMs() ?: throw e
    }

    while (true) {
        delay(delayMs)
        try {
            return embedded.verifyOob().await()         // approved
        } catch (e: EmbeddedAuthException) {
            delayMs = e.nextPushDelayMs() ?: throw e     // pending → loop; terminal → rethrow
        }
    }
}
```

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);
Handler handler = new Handler(Looper.getMainLooper());

// Next poll delay for a pending push, or null if the outcome is terminal.
Long nextPushDelayMs(EmbeddedAuthException e) {
    if (!(e.getError() instanceof EmbeddedAuthError.InsufficientAuthorization pending)) {
        return null;
    }
    for (NextAction action : pending.getNextActions()) {
        if (action instanceof NextAction.VerifyOob oob) {
            return (long) oob.getPollInMs();
        }
    }
    return null; // no pending VerifyOob → terminal
}

void pollPush(long delayMs) {
    handler.postDelayed(() ->
        embedded.verifyOob().start(new Callback<Credentials, EmbeddedAuthException>() {
            @Override public void onSuccess(Credentials credentials) {
                // approved: credentials.getAccessToken()
            }
            @Override public void onFailure(@NonNull EmbeddedAuthException exception) {
                Long next = nextPushDelayMs(exception);
                if (next != null) pollPush(next);   // pending → poll again
                // else terminal: inspect exception.getError()
            }
        }), delayMs);
}

// challengePush always continues; its continuation carries the first poll delay.
embedded.challengePush(0).start(new Callback<Void, EmbeddedAuthException>() {
    @Override public void onSuccess(Void result) { }
    @Override public void onFailure(@NonNull EmbeddedAuthException exception) {
        Long delay = nextPushDelayMs(exception);
        if (delay != null) pollPush(delay);
    }
});
```
</details>
