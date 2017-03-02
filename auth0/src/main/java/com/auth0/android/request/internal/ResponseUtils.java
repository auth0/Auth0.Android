package com.auth0.android.request.internal;

import java.io.Closeable;
import java.io.IOException;

class ResponseUtils {

    /**
     * Attempts to close a stream. No exception will be thrown if an IOException was raised.
     *
     * @param closeable the stream to close
     */
    static void closeStream(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignored) {
        }
    }
}
