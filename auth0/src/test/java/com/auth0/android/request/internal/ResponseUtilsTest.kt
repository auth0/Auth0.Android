package com.auth0.android.request.internal

import junit.framework.TestCase.assertTrue
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.junit.Test
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

public class ResponseUtilsTest {

    @Test
    public fun testIsNetworkErrorWhenSocketExceptionOccurs() {
        MatcherAssert.assertThat(ResponseUtils.isNetworkError(SocketException()), CoreMatchers.`is`(true))
    }

    @Test
    public fun testIsNetworkErrorWhenSocketTimeoutExceptionOccurs() {
        MatcherAssert.assertThat(ResponseUtils.isNetworkError(SocketTimeoutException()), CoreMatchers.`is`(true))
    }

    @Test
    public fun testIsNetworkErrorWhenUnknownHostExceptionOccurs() {
        MatcherAssert.assertThat(ResponseUtils.isNetworkError(UnknownHostException()), CoreMatchers.`is`(true))
    }
}