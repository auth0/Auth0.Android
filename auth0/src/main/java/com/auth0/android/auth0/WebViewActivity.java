/*
 * WebViewActivity.java
 *
 * Copyright (c) 2016 Auth0 (http://auth0.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.auth0.android.auth0;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

public class WebViewActivity extends AppCompatActivity {

    private static final String TAG = WebViewActivity.class.getSimpleName();
    private static final String KEY_REDIRECT_URI = "redirect_uri";

    public static final String CONNECTION_NAME_EXTRA = "serviceName";
    public static final String FULLSCREEN_EXTRA = "fullscreen";

    private WebView webView;
    private ProgressBar progressBar;
    private View errorView;
    private TextView errorMessage;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.v(TAG, "Creating a WebViewActivity for navigating to " + getIntent().getData().toString());
        super.onCreate(savedInstanceState);
        if (getIntent().getBooleanExtra(FULLSCREEN_EXTRA, false)) {
            setFullscreenMode();
        }

        setContentView(R.layout.com_auth0_lock_activity_web_view);
        final ActionBar bar = getSupportActionBar();
        if (bar != null) {
            String serviceName = getIntent().getStringExtra(CONNECTION_NAME_EXTRA);
            bar.setIcon(android.R.color.transparent);
            bar.setDisplayShowTitleEnabled(false);
            bar.setDisplayUseLogoEnabled(false);
            bar.setDisplayHomeAsUpEnabled(false);
            bar.setDisplayShowCustomEnabled(true);
            bar.setTitle(serviceName);
        }
        webView = (WebView) findViewById(R.id.com_auth0_lock_webview);
        webView.setVisibility(View.INVISIBLE);
        progressBar = (ProgressBar) findViewById(R.id.com_auth0_lock_progressbar);
        progressBar.setIndeterminate(true);
        progressBar.setMax(100);
        errorView = findViewById(R.id.com_auth0_lock_error_view);
        errorView.setVisibility(View.GONE);
        errorMessage = (TextView) findViewById(R.id.com_auth0_lock_text);
        Button retryButton = (Button) findViewById(R.id.com_auth0_lock_retry);
        retryButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                errorView.setVisibility(View.GONE);
                Log.v(TAG, "Retrying to load failed URL");
                startUrlLoading();
            }
        });

        startUrlLoading();
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (getIntent().getBooleanExtra(FULLSCREEN_EXTRA, false)) {
            setFullscreenMode();
        }
    }

    private void startUrlLoading() {
        if (!isNetworkAvailable()) {
            renderLoadError(getString(R.string.com_auth0_lock_network_error));
            return;
        }

        final Intent intent = getIntent();
        final Uri uri = intent.getData();
        final String redirectUrl = uri.getQueryParameter(KEY_REDIRECT_URI);
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                super.onProgressChanged(view, newProgress);
                if (newProgress > 0) {
                    progressBar.setIndeterminate(false);
                    progressBar.setProgress(newProgress);
                }
            }
        });
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (url.startsWith(redirectUrl)) {
                    Log.v(TAG, "Redirect URL was called");
                    final Intent intent = new Intent();
                    intent.setData(Uri.parse(url));
                    setResult(RESULT_OK, intent);
                    finish();
                    return true;
                }
                return false;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                progressBar.setProgress(0);
                progressBar.setIndeterminate(true);
                progressBar.setVisibility(View.GONE);
                final boolean isShowingError = errorView.getVisibility() == View.VISIBLE;
                webView.setVisibility(isShowingError ? View.INVISIBLE : View.VISIBLE);
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                super.onPageStarted(view, url, favicon);
                progressBar.setProgress(0);
                progressBar.setVisibility(View.VISIBLE);
            }

            @SuppressWarnings("deprecation")
            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                Log.w(TAG, String.format("Load error (%d) %s", errorCode, description));
                renderLoadError(description);
                super.onReceivedError(view, errorCode, description, failingUrl);
            }

            @TargetApi(Build.VERSION_CODES.M)
            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                Log.w(TAG, String.format("Load error (%d) %s", error.getErrorCode(), error.getDescription()));
                renderLoadError(error.getDescription().toString());
                super.onReceivedError(view, request, error);
            }

        });
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setSupportZoom(true);
        webView.getSettings().setBuiltInZoomControls(true);
        webView.loadUrl(uri.toString());
    }

    private void renderLoadError(String description) {
        errorMessage.setText(description);
        webView.setVisibility(View.INVISIBLE);
        errorView.setVisibility(View.VISIBLE);
    }

    private boolean isNetworkAvailable() {
        boolean available = true;
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        try {
            NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
            available = activeNetworkInfo != null && activeNetworkInfo.isConnectedOrConnecting();
            Log.v(TAG, "Is network available? " + available);
        } catch (SecurityException e) {
            Log.w(TAG, "Could not check for Network status. Please, be sure to include the android.permission.ACCESS_NETWORK_STATE permission in the manifest");
        }
        return available;
    }

    private void setFullscreenMode() {
        Log.d(TAG, "Activity in fullscreen mode");
        final Window window = getWindow();
        if (Build.VERSION.SDK_INT >= 16) {
            View decorView = window.getDecorView();
            int uiOptions = View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN;
            decorView.setSystemUiVisibility(uiOptions);
        } else {
            window.setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);
        }
    }
}