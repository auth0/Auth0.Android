package com.auth0.android.request.internal

import java.io.InputStream
import java.io.InputStreamReader
import java.nio.charset.Charset

/**
 * InputStreamReader implementation that remembers if it was called Closeable#close().
 */
internal class AwareInputStreamReader(inputStream: InputStream, charset: Charset) :
    InputStreamReader(inputStream, charset) {
    var isClosed: Boolean = false
        private set

    override fun close() {
        super.close()
        this.isClosed = true
    }

}