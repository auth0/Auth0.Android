package com.auth0.android.request

import java.io.IOException
import java.io.Reader

/**
 * Adapter that converts a JSON input into the <T> class that represents a result.
 */
public interface JsonAdapter<T> {

    /**
     * Converts the JSON input given in the Reader to the <T> instance.
     * @param reader the reader that contains the JSON encoded string.
     * @param metadata optional metadata that can be passed along .
     * @throws IOException could be thrown to signal that the input was invalid.
     * @return the parsed <T> result
     */
    @Throws(IOException::class)
    public fun fromJson(reader: Reader, metadata: Map<String, Any> = emptyMap() ): T

}