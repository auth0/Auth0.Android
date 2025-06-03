package com.auth0.android.util

import com.auth0.android.callback.MyAccountCallback
import com.auth0.android.myaccount.MyAccountException
import com.google.gson.reflect.TypeToken
import com.jayway.awaitility.Awaitility.await
import com.jayway.awaitility.core.ConditionTimeoutException
import org.hamcrest.BaseMatcher
import org.hamcrest.Description
import org.hamcrest.Matcher
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.isA
import org.hamcrest.Matchers.notNullValue
import org.hamcrest.Matchers.nullValue

public class MyAccountCallbackMatcher<T>(
    private val payloadMatcher: Matcher<in T?>,
    private val errorMatcher: Matcher<in MyAccountException?>
) : BaseMatcher<MyAccountCallback<T>>() {


    @Suppress("UNCHECKED_CAST")
    override fun matches(item: Any): Boolean {
        val callback = item as MockMyAccountCallback<T>
        return try {
            await().until(callback.payload(), payloadMatcher)
            await().until(callback.error(), errorMatcher)
            true
        } catch (e: ConditionTimeoutException) {
            false
        }
    }

    override fun describeTo(description: Description) {
        description.appendText("successful method be called")
    }

    public companion object {
        @JvmStatic
        public fun <T> hasPayloadOfType(tClazz: Class<T>): Matcher<MyAccountCallback<T>> {
            return MyAccountCallbackMatcher(
                isA(tClazz),
                nullValue(MyAccountException::class.java)
            )
        }

        @JvmStatic
        public fun <T> hasPayloadOfType(typeToken: TypeToken<T>): Matcher<MyAccountCallback<T>> {
            return MyAccountCallbackMatcher(
                TypeTokenMatcher.isA(typeToken),
                nullValue(MyAccountException::class.java)
            )
        }

        @JvmStatic
        public fun <T> hasPayload(payload: T): Matcher<MyAccountCallback<T>> {
            return MyAccountCallbackMatcher(
                equalTo(payload),
                nullValue(MyAccountException::class.java)
            )
        }

        @JvmStatic
        public fun <T> hasNoPayloadOfType(tClazz: Class<T>): Matcher<MyAccountCallback<T>> {
            return MyAccountCallbackMatcher(
                nullValue(tClazz),
                notNullValue(MyAccountException::class.java)
            )
        }

        @JvmStatic
        public fun <T> hasNoPayloadOfType(typeToken: TypeToken<T>): Matcher<MyAccountCallback<T>> {
            return MyAccountCallbackMatcher(
                TypeTokenMatcher.isA(typeToken),
                nullValue(MyAccountException::class.java)
            )
        }

        @JvmStatic
        public fun hasNoError(): Matcher<MyAccountCallback<Void>> {
            return MyAccountCallbackMatcher(
                notNullValue(Void::class.java),
                nullValue(MyAccountException::class.java)
            )
        }

        @JvmStatic
        public fun hasError(): Matcher<MyAccountCallback<Void>> {
            return MyAccountCallbackMatcher(
                nullValue(Void::class.java),
                notNullValue(MyAccountException::class.java)
            )
        }
    }
}