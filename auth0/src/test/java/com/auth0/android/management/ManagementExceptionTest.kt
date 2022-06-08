package com.auth0.android.management

import com.auth0.android.NetworkErrorException
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.junit.Test
import java.io.IOException

public class ManagementExceptionTest {
    @Test
    public fun shouldNotHaveNetworkError() {
        val ex = ManagementException("Something else happened")
        MatcherAssert.assertThat(ex.isNetworkError, CoreMatchers.`is`(false))
    }

    @Test
    public fun shouldHaveNetworkError() {
        val ex = ManagementException(
            "Request has definitely failed", NetworkErrorException(
                IOException()
            )
        )
        MatcherAssert.assertThat(ex.isNetworkError, CoreMatchers.`is`(true))
    }
}