package com.auth0.android.request.kt

import android.net.Uri
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

//TODO: Should this be internal?
public class DefaultClient(private val timeout: Int) : NetworkingClient {

    /**
     * Creates and executes a networking request blocking
     */
    @Throws(IllegalArgumentException::class, IOException::class)
    override fun load(url: String, options: RequestOptions): ServerResponse {
        val parsedUri = Uri.parse(url)
        //FIXME: Probably best to check this in the AuthenticationAPIClient constructor
        if (parsedUri.scheme != "https") {
            throw IllegalArgumentException("The URL must use HTTPS")
        }

        //prepare URL
        val targetUrl = if (options.method == HttpMethod.GET) {
            val uriBuilder = parsedUri.buildUpon()
            //setup query
            options.parameters.map {
                uriBuilder.appendQueryParameter(it.key, it.value)
            }
            URL(uriBuilder.build().toString())
        } else {
            URL(url)
        }

        val connection: HttpsURLConnection = targetUrl.openConnection() as HttpsURLConnection

        //setup timeout
        connection.connectTimeout = timeout
        connection.readTimeout = timeout

        //setup headers
        options.headers.map { connection.setRequestProperty(it.key, it.value) }

        if (options.method == HttpMethod.POST) {
            connection.doOutput = true
            //TODO: iterate over the params and construct a body
        }

        //probably best to explicitly call connect
        connection.connect()

        return ServerResponse(
            connection.responseCode,
            connection.errorStream ?: connection.inputStream,
            connection.headerFields
        )
    }


}