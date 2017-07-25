package com.auth0.android.provider;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;

public class AuthenticationActivity extends Activity {

    static final String EXTRA_USE_BROWSER = "com.auth0.android.EXTRA_USE_BROWSER";
    static final String EXTRA_USE_FULL_SCREEN = "com.auth0.android.EXTRA_USE_FULL_SCREEN";
    static final String EXTRA_CONNECTION_NAME = "com.auth0.android.EXTRA_CONNECTION_NAME";
    private static final String EXTRA_INTENT_LAUNCHED = "com.auth0.android.EXTRA_INTENT_LAUNCHED";

    private boolean intentLaunched;
    private CustomTabsController customTabsController;

    static void authenticateUsingBrowser(Context context, Uri authorizeUri) {
        Intent intent = new Intent(context, AuthenticationActivity.class);
        intent.setData(authorizeUri);
        intent.putExtra(AuthenticationActivity.EXTRA_USE_BROWSER, true);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        context.startActivity(intent);
    }

    static void authenticateUsingWebView(Activity activity, Uri authorizeUri, int requestCode, String connection, boolean useFullScreen) {
        Intent intent = new Intent(activity, AuthenticationActivity.class);
        intent.setData(authorizeUri);
        intent.putExtra(AuthenticationActivity.EXTRA_USE_BROWSER, false);
        intent.putExtra(AuthenticationActivity.EXTRA_USE_FULL_SCREEN, useFullScreen);
        intent.putExtra(AuthenticationActivity.EXTRA_CONNECTION_NAME, connection);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        activity.startActivityForResult(intent, requestCode);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            deliverSuccessfulAuthenticationResult(data);
        }
        finish();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(EXTRA_INTENT_LAUNCHED, intentLaunched);
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (savedInstanceState != null) {
            intentLaunched = savedInstanceState.getBoolean(EXTRA_INTENT_LAUNCHED, false);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!intentLaunched) {
            intentLaunched = true;
            launchAuthenticationIntent();
            return;
        }

        if (getIntent().getData() != null) {
            deliverSuccessfulAuthenticationResult(getIntent());
        }
        finish();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (customTabsController != null) {
            customTabsController.unbindService();
            customTabsController = null;
        }
    }

    private void launchAuthenticationIntent() {
        Bundle extras = getIntent().getExtras();
        final Uri authorizeUri = getIntent().getData();
        if (!extras.getBoolean(EXTRA_USE_BROWSER, true)) {
            Intent intent = new Intent(this, WebAuthActivity.class);
            intent.setData(authorizeUri);
            intent.putExtra(WebAuthActivity.CONNECTION_NAME_EXTRA, extras.getString(EXTRA_CONNECTION_NAME));
            intent.putExtra(WebAuthActivity.FULLSCREEN_EXTRA, extras.getBoolean(EXTRA_USE_FULL_SCREEN));
            //The request code value can be ignored
            startActivityForResult(intent, 33);
            return;
        }

        customTabsController = createCustomTabsController(this);
        customTabsController.bindService();
        customTabsController.launchUri(authorizeUri);
    }

    @VisibleForTesting
    CustomTabsController createCustomTabsController(@NonNull Context context) {
        return new CustomTabsController(context);
    }

    @VisibleForTesting
    void deliverSuccessfulAuthenticationResult(Intent result) {
        WebAuthProvider.resume(result);
    }

}
