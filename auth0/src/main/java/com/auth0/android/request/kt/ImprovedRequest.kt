package com.auth0.android.request.kt;

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.BaseCallback
import com.google.gson.TypeAdapter
import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.Charset

//FIXME: Make this internal once the API Client begins returning interfaces
public class ImprovedRequest<T, U : Auth0Exception>(
    method: HttpMethod,
    private val url: String,
    private val client: NetworkingClient,
    private val jsonAdapter: TypeAdapter<T>,
    private val errorBuilder: ErrorBuilder<U>
) {
    //properties
    private val requestOptions = RequestOptions(method)

    //functions
    public fun withParameter(name: String, value: String): ImprovedRequest<T, U> {
        requestOptions.parameters[name] = value
        return this
    }

    public fun withHeader(name: String, value: String): ImprovedRequest<T, U> {
        requestOptions.headers[name] = value
        return this
    }

    public fun start(callback: BaseCallback<T, U>) {
        ThreadUtils.executorService.execute {
            val response: ServerResponse
            try {
                response = client.load(url, requestOptions)
            } catch (exception: IOException) {
                //1. Network exceptions, timeouts, etc
                ThreadUtils.mainThreadHandler.post {
                    val error =
                        errorBuilder.fromException("Network error!", exception)
                    callback.onFailure(error)
                }
                return@execute
            }

            val reader = InputStreamReader(response.body, Charset.defaultCharset())
            if (response.isSuccess()) {
                //2. Successful scenario. Response of type T
                val result = jsonAdapter.fromJson(reader)
                ThreadUtils.mainThreadHandler.post {
                    callback.onSuccess(result)
                }
            } else {
                //3. Error scenario. Response of type U
                val error = errorBuilder.fromJson(reader)
                ThreadUtils.mainThreadHandler.post {
                    callback.onFailure(error)
                }
            }
        }
    }
}
