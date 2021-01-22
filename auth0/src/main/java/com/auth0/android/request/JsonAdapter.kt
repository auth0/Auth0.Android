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
     * @throws IOException could be thrown to signal that the input was invalid.
     * @return the parsed <T> result
     */
    @Throws(IOException::class)
    public fun fromJson(reader: Reader): T

}