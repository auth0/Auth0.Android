package com.auth0.android.request.internal

import com.auth0.android.request.HttpMethod
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import com.squareup.okhttp.*
import java.io.IOException

//TODO: Should this be internal?
private class OkClient(timeout: Int) : NetworkingClient {
    private val okClient: OkHttpClient = OkHttpClientFactory().createClient(
        true, true, timeout, timeout, timeout
    )

    /**
     * Creates and executes a networking request blocking
     */
    @Throws(IllegalArgumentException::class, IOException::class)
    override fun load(url: String, options: RequestOptions): ServerResponse {
        val httpUrl = HttpUrl.parse(url)
        //FIXME: Probably best to check this in the AuthenticationAPIClient constructor
        if (!httpUrl.isHttps) {
            throw IllegalArgumentException("The URL must use HTTPS")
        }

        val call = prepareCall(httpUrl, options)
        val response = call.execute()

        return ServerResponse(
            response.code(),
            response.body().byteStream(),
            response.headers().toMultimap()
        )
    }

    private fun prepareCall(url: HttpUrl, options: RequestOptions): Call {
        val requestBuilder = Request.Builder()
        val urlBuilder = url.newBuilder()

        when (options.method) {
            is HttpMethod.GET -> {
                //add parameters as query
                options.parameters.map { urlBuilder.addQueryParameter(it.key, it.value) }
                requestBuilder.get()
            }
            is HttpMethod.POST -> {
                //add parameters as body
                val body: RequestBody = null!! //TODO() use OkHttp v4 FormBody
                requestBuilder.post(body)
            }
        }
        val request = requestBuilder
            .url(urlBuilder.build())
            .headers(Headers.of(options.headers))
            .build()
        return okClient.newCall(request)
    }

}