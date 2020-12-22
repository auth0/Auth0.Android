package com.auth0.android.request

import android.net.Uri
import com.auth0.android.request.internal.GsonProvider
import com.google.gson.Gson
import java.io.BufferedWriter
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Default implementation of a Networking Client. Makes use of HttpUrlConnection.
 * @param timeout the connection timeout to use when executing requests.
 */
//TODO: Should this be internal?
public class DefaultClient(private val timeout: Int) : NetworkingClient {

    //TODO: receive this via constructor parameters
    private val gson: Gson = GsonProvider.buildGson()

    /**
     * Creates and executes a networking request blocking the current thread.
     * @return the response from the server.
     */
    @Throws(IllegalArgumentException::class, IOException::class)
    override fun load(url: String, options: RequestOptions): ServerResponse {
        val parsedUri = Uri.parse(url)

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

        val connection = getHttpUrlConnection(targetUrl)

        //FIXME: setup timeout
//        connection.connectTimeout = timeout
//        connection.readTimeout = timeout

        //setup headers
        options.headers.map { connection.setRequestProperty(it.key, it.value) }

        if (options.method == HttpMethod.POST || options.method == HttpMethod.PATCH || options.method == HttpMethod.DELETE) {
            //required headers
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.doInput = true
            connection.doOutput = true
            connection.requestMethod = options.method.toString()
            val output = connection.outputStream
            val writer = BufferedWriter(output.bufferedWriter())
            if (options.parameters.isNotEmpty()) {
                val json = gson.toJson(options.parameters)
                writer.write(json)
            }
            writer.flush()
            writer.close()
            output.close()
        }

        connection.connect()

        return ServerResponse(
            connection.responseCode,
            connection.errorStream ?: connection.inputStream,
            connection.headerFields
        )
    }

    private fun getHttpUrlConnection(targetUrl: URL): HttpURLConnection {
        // Auth0 constructor will enforce HTTPS scheme. This is here to enable running
        // tests with MockWebServer using HTTP.
        if (targetUrl.protocol == "http") {
            return targetUrl.openConnection() as HttpURLConnection
        } else {
            return targetUrl.openConnection() as HttpsURLConnection
        }
    }
}