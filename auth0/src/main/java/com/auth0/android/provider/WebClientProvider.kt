package com.auth0.android.provider

import android.webkit.CookieManager
import android.webkit.WebView
import com.auth0.android.Auth0

/**
 * Provider class to handle native to web sso
 */
public object WebClientProvider {
    private const val TAG = "WebSSOProvider"

    public fun configureSSOWebView(
        account: Auth0,
        url: String,
        webView: WebView,
        sessionToken: String,
    ): WebView {
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setCookie(
            url,
            "session_token=$sessionToken; path=/"
        )
        return webView
    }
}