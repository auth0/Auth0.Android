package com.auth0.android.callback

import com.auth0.android.authentication.AuthenticationException

public interface AuthenticationCallback<T> : Callback<T, AuthenticationException>