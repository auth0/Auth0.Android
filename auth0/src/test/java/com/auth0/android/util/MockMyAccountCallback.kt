package com.auth0.android.util

import com.auth0.android.callback.MyAccountCallback
import com.auth0.android.myaccount.MyAccountException
import java.util.concurrent.Callable

public class MockMyAccountCallback<T> : MyAccountCallback<T> {

    private var error: MyAccountException? = null
    private var payload: T? = null

    override fun onSuccess(result: T) {
        this.payload = result
    }

    override fun onFailure(error: MyAccountException) {
        this.error = error
    }

    public fun error(): Callable<MyAccountException?> = Callable { error }

    public fun payload(): Callable<T?> = Callable { payload }

    public fun getError(): MyAccountException? = error

    public fun getPayload(): T? = payload
}