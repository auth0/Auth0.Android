# Recovery Code Verification & Confirmation

Recovery-code MFA is always two steps:

1. `verifyRecoveryCode` validates the user's code. It **never** returns `Credentials` — it
   always continues with a `NextAction.ConfirmRecoveryCode` carrying a server-rotated new code.
2. `confirmRecoveryCode` acknowledges that new code (show it to the user first) and is
   terminal — it returns `Credentials`.

```kotlin
val embedded = EmbeddedAuthClient(Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN"))

// The rotated recovery code carried by a ConfirmRecoveryCode continuation, if present.
private fun EmbeddedAuthException.rotatedRecoveryCode(): String? =
    (error as? EmbeddedAuthError.InsufficientAuthorization)
        ?.nextActions?.filterIsInstance<NextAction.ConfirmRecoveryCode>()
        ?.firstOrNull()?.newCode

// 1. Verify the current recovery code — always continues, never returns Credentials.
try {
    embedded.verifyRecoveryCode("ABCD-1234-EFGH-5678").await()
} catch (e: EmbeddedAuthException) {
    val newCode = e.rotatedRecoveryCode() ?: throw e
    // Show newCode to the user so they can save their new recovery code.
}

// 2. Acknowledge the rotated code and complete the flow. Terminal — returns Credentials.
val credentials = embedded.confirmRecoveryCode().await()
// credentials.accessToken, credentials.idToken, ...
```

<details>
  <summary>Using Java</summary>

```java
Auth0 auth0 = Auth0.getInstance("YOUR_CLIENT_ID", "YOUR_DOMAIN");
EmbeddedAuthClient embedded = new EmbeddedAuthClient(auth0);

embedded.verifyRecoveryCode("ABCD-1234-EFGH-5678")
    .start(new Callback<Void, EmbeddedAuthException>() {
        @Override public void onSuccess(Void result) { }
        @Override public void onFailure(@NonNull EmbeddedAuthException e) {
            if (!(e.getError() instanceof EmbeddedAuthError.InsufficientAuthorization pending)) {
                return; // terminal: inspect e.getError()
            }
            String newCode = null;
            for (NextAction action : pending.getNextActions()) {
                if (action instanceof NextAction.ConfirmRecoveryCode confirm) {
                    newCode = confirm.getNewCode();
                    break;
                }
            }
            if (newCode == null) return;
            // Show newCode to the user, then acknowledge:
            embedded.confirmRecoveryCode()
                .start(new Callback<Credentials, EmbeddedAuthException>() {
                    @Override public void onSuccess(Credentials credentials) {
                        // credentials.getAccessToken()
                    }
                    @Override public void onFailure(@NonNull EmbeddedAuthException ex) { }
                });
        }
    });
```
</details>
