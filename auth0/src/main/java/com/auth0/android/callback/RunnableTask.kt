package com.auth0.android.callback

internal interface RunnableTask<T> {
    fun apply(t: T)
}