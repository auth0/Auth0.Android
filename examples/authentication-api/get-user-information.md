### Get user information

```kotlin
authentication
   .userInfo("user access_token")
   .start(object: Callback<UserProfile, AuthenticationException> {
       override fun onFailure(exception: AuthenticationException) { }

       override fun onSuccess(profile: UserProfile) { }
   })
```

<details>
  <summary>Using coroutines</summary>

```kotlin
try {
    val user = authentication
        .userInfo("user access_token")
        .await()
    println(user)
} catch (e: AuthenticationException) {
    e.printStacktrace()
}
```
</details>

<details>
  <summary>Using Java</summary>

```java
authentication
   .userInfo("user access_token")
   .start(new Callback<UserProfile, AuthenticationException>() {
       @Override
       public void onSuccess(@Nullable UserProfile payload) {
           //Got the profile!
       }

       @Override
       public void onFailure(@NonNull AuthenticationException error) {
           //Error!
       }
   });
```
</details>
