package com.auth0.android.provider;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

public class AuthenticationActivity extends Activity {

    static final String EXTRA_USE_BROWSER = "com.auth0.android.EXTRA_USE_BROWSER";
    static final String EXTRA_USE_FULL_SCREEN = "com.auth0.android.EXTRA_USE_FULL_SCREEN";
    static final String EXTRA_CONNECTION_NAME = "com.auth0.android.EXTRA_CONNECTION_NAME";
    static final String EXTRA_AUTHORIZE_URI = "com.auth0.android.EXTRA_AUTHORIZE_URI";
    static final String EXTRA_CT_OPTIONS = "com.auth0.android.EXTRA_CT_OPTIONS";
    private static final String EXTRA_INTENT_LAUNCHED = "com.auth0.android.EXTRA_INTENT_LAUNCHED";

    private boolean intentLaunched;
    private CustomTabsController customTabsController;

    static void authenticateUsingBrowser(@NonNull Context context, @NonNull Uri authorizeUri, @NonNull CustomTabsOptions options) {
        Intent intent = new Intent(context, AuthenticationActivity.class);
        intent.putExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI, authorizeUri);
        intent.putExtra(AuthenticationActivity.EXTRA_USE_BROWSER, true);
        intent.putExtra(AuthenticationActivity.EXTRA_CT_OPTIONS, options);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        context.startActivity(intent);
    }

    static void authenticateUsingWebView(@NonNull Activity activity, @NonNull Uri authorizeUri, int requestCode, String connection, boolean useFullScreen) {
        Intent intent = new Intent(activity, AuthenticationActivity.class);
        intent.putExtra(AuthenticationActivity.EXTRA_AUTHORIZE_URI, authorizeUri);
        intent.putExtra(AuthenticationActivity.EXTRA_USE_BROWSER, false);
        intent.putExtra(AuthenticationActivity.EXTRA_USE_FULL_SCREEN, useFullScreen);
        intent.putExtra(AuthenticationActivity.EXTRA_CONNECTION_NAME, connection);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        activity.startActivityForResult(intent, requestCode);
    }

    @Override
    protected void onNewIntent(@Nullable Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        if (resultCode == RESULT_CANCELED) {
            data = new Intent();
        }
        deliverAuthenticationResult(data);
        finish();
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
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
        final Intent authenticationIntent = getIntent();
        if (!intentLaunched && authenticationIntent.getExtras() == null) {
            //Activity was launched in an unexpected way
            finish();
            return;
        } else if (!intentLaunched) {
            intentLaunched = true;
            launchAuthenticationIntent();
            return;
        }

        boolean resultMissing = authenticationIntent.getData() == null;
        if (resultMissing) {
            setResult(RESULT_CANCELED);
        }
        deliverAuthenticationResult(authenticationIntent);
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
        //noinspection ConstantConditions
        Uri authorizeUri = extras.getParcelable(EXTRA_AUTHORIZE_URI);
        if (!extras.getBoolean(EXTRA_USE_BROWSER, true)) {
            Intent intent = new Intent(this, WebAuthActivity.class);
            intent.setData(authorizeUri);
            intent.putExtra(WebAuthActivity.CONNECTION_NAME_EXTRA, extras.getString(EXTRA_CONNECTION_NAME));
            intent.putExtra(WebAuthActivity.FULLSCREEN_EXTRA, extras.getBoolean(EXTRA_USE_FULL_SCREEN));
            //The request code value can be ignored
            startActivityForResult(intent, 33);
            return;
        }

        CustomTabsOptions customTabsOptions = extras.getParcelable(EXTRA_CT_OPTIONS);
        //noinspection ConstantConditions
        customTabsController = createCustomTabsController(this, customTabsOptions);
        customTabsController.bindService();
        //noinspection ConstantConditions
        customTabsController.launchUri(authorizeUri);
    }

    @VisibleForTesting
    CustomTabsController createCustomTabsController(@NonNull Context context, @NonNull CustomTabsOptions options) {
        return new CustomTabsController(context, options);
    }

    @VisibleForTesting
    void deliverAuthenticationResult(@Nullable Intent result) {
        WebAuthProvider.resume(result);
    }

}
