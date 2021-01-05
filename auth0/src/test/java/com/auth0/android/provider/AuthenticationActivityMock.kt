package com.auth0.android.provider

import android.content.Context
import android.content.Intent

public class AuthenticationActivityMock : AuthenticationActivity() {
    internal var customTabsController: CustomTabsController? = null
    public var deliveredIntent: Intent? = null
        private set

    override fun createCustomTabsController(
        context: Context,
        options: CustomTabsOptions
    ): CustomTabsController {
        return customTabsController!!
    }

    override fun deliverAuthenticationResult(result: Intent?) {
        deliveredIntent = result
        super.deliverAuthenticationResult(result)
    }
}