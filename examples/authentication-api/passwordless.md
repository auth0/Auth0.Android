### Passwordless Login

This feature requires your Application to have the *Passwordless OTP* enabled. See [this article](https://auth0.com/docs/clients/client-grant-types) to learn how to enable it.

Passwordless is a 2 step flow:

#### Step 1: Request the code

```kotlin
authentication
    .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
    .start(object: Callback<Void, AuthenticationException> {
        override fun onFailure(exception: AuthenticationException) { }

        override fun onSuccess(result: Void?) { }
    })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val result = authentication
        .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
        .await()
    println(result)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
    .passwordlessWithEmail("info@auth0.com", PasswordlessType.CODE, "my-passwordless-connection")
    .start(new Callback<Void, AuthenticationException>() {
        @Override
        public void onSuccess(Void payload) {
            //Code sent!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

#### Step 2: Input the code

```kotlin
authentication
    .loginWithEmail("info@auth0.com", "123456", "my-passwordless-connection")
    .validateClaims() //mandatory
    .start(object: Callback<Credentials, AuthenticationException> {
       override fun onFailure(exception: AuthenticationException) { }

       override fun onSuccess(credentials: Credentials) { }
   })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val credentials = authentication
        .loginWithEmail("info@auth0.com", "123456", "my-passwordless-connection")
        .validateClaims()
        .await()
    println(credentials)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>


<details>
  <summary>Using Java</summary>

```java
authentication
    .loginWithEmail("info@auth0.com", "123456", "my-passwordless-connection")
    .validateClaims() //mandatory
    .start(new Callback<Credentials, AuthenticationException>() {
        @Override
        public void onSuccess(@Nullable Credentials payload) {
            //Logged in!
        }

        @Override
        public void onFailure(@NonNull AuthenticationException error) {
            //Error!
        }
    });
```
</details>

> The default scope used is `openid profile email`. Regardless of the scopes set to the request, the `openid` scope is always enforced.
