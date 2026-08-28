## Networking client customization

This library provides the ability to customize the behavior of the networking client for common configurations, as well the ability to define and use your own networking client implementation.

The Auth0 class can be configured with a `NetworkingClient`, which will be used when making requests. You can configure the default client with custom timeout values, any headers that should be sent on all requests, and whether to log request/response info (for non-production debugging purposes only). For more advanced configuration, you can provide your own implementation of `NetworkingClient`.

### Timeout configuration

```kotlin
val netClient = DefaultClient.Builder()
    .connectTimeout(30)
    .readTimeout(30)
    .writeTimeout(30)  
    .callTimeout(120) 
    .build()

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
DefaultClient netClient = new DefaultClient.Builder()
    .connectTimeout(30)
    .readTimeout(30)
    .writeTimeout(30)
    .callTimeout(120)
    .build();
Auth0 account = Auth0.getInstance("client id", "domain");
account.setNetworkingClient(netClient);
```
</details>

### Logging configuration

```kotlin
val netClient = DefaultClient.Builder()
    .enableLogging(true)
    .build()

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

You can also provide a custom logger to control where logs are written:

```kotlin
val netClient = DefaultClient.Builder()
    .enableLogging(true)
    .logger(HttpLoggingInterceptor.Logger { message -> Log.d("Auth0Http", message) })
    .build()
```

<details>
  <summary>Using Java</summary>

```java
DefaultClient netClient = new DefaultClient.Builder()
    .enableLogging(true)
    .build();
Auth0 account = Auth0.getInstance("client id", "domain");
account.setNetworkingClient(netClient);
```
</details>

### Set additional headers for all requests

```kotlin
val netClient = DefaultClient.Builder()
    .defaultHeaders(mapOf("{HEADER-NAME}" to "{HEADER-VALUE}"))
    .build()

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = netClient
```

<details>
  <summary>Using Java</summary>

```java
Map<String, String> defaultHeaders = new HashMap<>();
defaultHeaders.put("{HEADER-NAME}", "{HEADER-VALUE}");

DefaultClient netClient = new DefaultClient.Builder()
    .defaultHeaders(defaultHeaders)
    .build();
Auth0 account = Auth0.getInstance("client id", "domain");
account.setNetworkingClient(netClient);
```
</details>

### Advanced configuration

For more advanced configuration of the networking client, you can provide a custom implementation of `NetworkingClient`. This may be useful when you wish to reuse your own networking client, configure a proxy, etc.

```kotlin
class CustomNetClient : NetworkingClient {
    override fun load(url: String, options: RequestOptions): ServerResponse {
         // Create and execute the request to the specified URL with the given options
         val response = // ...

         // Return a ServerResponse from the received response data
         return ServerResponse(responseCode, responseBody, responseHeaders)
    }
}

val account = Auth0.getInstance("{YOUR_CLIENT_ID}", "{YOUR_DOMAIN}")
account.networkingClient = CustomNetClient()
```

<details>
  <summary>Using Java</summary>

```java
class CustomNetClient extends NetworkingClient {
   @Override
   public ServerResponse load(String url) {
      // Create and execute the request to the specified URL with the given options
      ServerResponse response = // ...

      // Return a ServerResponse from the received response data
      return new ServerResponse(responseCode, responseBody, responseHeaders);
   }  
};

Auth0 account = Auth0.getInstance("client id", "domain");
account.networkingClient = new CustomNetClient();
```
</details>
