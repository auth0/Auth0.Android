package com.auth0.android.request.internal

import java.io.Closeable
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

internal object ResponseUtils {
    /**
     * Attempts to close a stream. No exception will be thrown if an IOException was raised.
     *
     * @param closeable the stream to close
     */
    fun closeStream(closeable: Closeable) {
        try {
            closeable.close()
        } catch (ignored: IOException) {
        }
    }

    /**
     * Checks if the given Throwable is a network error.
     */
    fun isNetworkError(cause: Throwable?): Boolean {
        return (cause is SocketException || cause is SocketTimeoutException
                || cause is UnknownHostException)
    }
}
