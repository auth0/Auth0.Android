package com.auth0.android.provider

import com.auth0.android.Auth0Exception
import com.auth0.android.callback.Callback

/**
 * Generic callback called on success/failure, that receives no payload when succeeds.
 */
internal interface VoidCallback : Callback<Void?, Auth0Exception>