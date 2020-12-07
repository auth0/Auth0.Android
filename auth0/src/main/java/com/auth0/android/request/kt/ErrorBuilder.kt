package com.auth0.android.request.kt

import com.auth0.android.Auth0Exception
import java.io.Reader

public interface ErrorBuilder<out U : Auth0Exception> {

    public fun fromJson(reader: Reader): U
    public fun fromException(message: String, exception: Exception): U
}