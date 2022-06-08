package com.auth0.android.request.internal

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import org.junit.Ignore
import java.io.FileNotFoundException
import java.io.FileReader
import java.io.IOException
import java.io.Reader

@Ignore
public abstract class GsonBaseTest {
    internal lateinit var gson: Gson

    @Throws(IOException::class)
    internal fun <T> pojoFrom(json: Reader, typeToken: TypeToken<T>): T {
        return gson.getAdapter(typeToken).fromJson(json)
    }

    @Throws(IOException::class)
    internal fun <T> pojoFrom(json: Reader, clazz: Class<T>): T {
        return gson.getAdapter(clazz).fromJson(json)
    }

    @Throws(FileNotFoundException::class)
    internal fun json(name: String): FileReader {
        return FileReader(name)
    }

    internal companion object {
        internal const val EMPTY_OBJECT = "src/test/resources/empty_object.json"
        internal const val INVALID = "src/test/resources/invalid.json"
    }
}