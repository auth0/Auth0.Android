package com.auth0.android.provider;

import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.VisibleForTesting;
import android.support.customtabs.CustomTabsClient;
import android.support.customtabs.CustomTabsIntent;
import android.support.customtabs.CustomTabsServiceConnection;
import android.support.customtabs.CustomTabsSession;
import android.util.Log;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

class CustomTabsController extends CustomTabsServiceConnection {

    private static final String TAG = CustomTabsController.class.getSimpleName();
    private static final String ACTION_CUSTOM_TABS_CONNECTION = "android.support.customtabs.action.CustomTabsService";
    //Known Browsers
    private static final String CHROME_STABLE = "com.android.chrome";
    private static final String CHROME_SYSTEM = "com.google.android.apps.chrome";
    private static final String CHROME_BETA = "com.android.chrome.beta";
    private static final String CHROME_DEV = "com.android.chrome.dev";

    private final WeakReference<Context> context;
    private final String preferredPackage;
    private CustomTabsSession session;
    private Uri nextUri;
    private boolean isBound;

    @VisibleForTesting
    CustomTabsController(@NonNull Context context, @NonNull String browserPackage) {
        this.context = new WeakReference<>(context);
        this.preferredPackage = browserPackage;
    }

    public CustomTabsController(@NonNull Context context) {
        this(context, getBestBrowserPackage(context));
    }

    @VisibleForTesting
    void clearContext() {
        this.context.clear();
    }

    @Override
    public void onCustomTabsServiceConnected(ComponentName componentName, CustomTabsClient customTabsClient) {
        Log.d(TAG, "CustomTabs Service connected");
        isBound = true;
        if (customTabsClient != null) {
            customTabsClient.warmup(0L);
            session = customTabsClient.newSession(null);
        }
        if (nextUri != null) {
            launchUri(nextUri);
        }
    }

    @Override
    public void onServiceDisconnected(ComponentName componentName) {
        Log.d(TAG, "CustomTabs Service disconnected");
        session = null;
    }

    /**
     * Attempts to bind the Custom Tabs Service to the Context.
     *
     * @return true if the request to bind the service was successful, false if the service was already bound or it couldn't be bound.
     */
    public boolean bindService() {
        Log.v(TAG, "Trying to bind the service");
        Context context = this.context.get();
        boolean success = false;
        if (!isBound && context != null) {
            success = CustomTabsClient.bindCustomTabsService(context, preferredPackage, this);
        }
        Log.d(TAG, "Bound: " + success);
        return success;
    }

    /**
     * Attempts to unbind the Custom Tabs Service from the Context.
     */
    public void unbindService() {
        Log.v(TAG, "Trying to unbind the service");
        Context context = this.context.get();
        if (isBound && context != null) {
            context.unbindService(this);
        }
        this.isBound = false;
        this.nextUri = null;
    }

    /**
     * Attempst to bind the Custom Tabs Service to the Context and opens a Uri as soon as possible.
     *
     * @param uri the uri to open in a Custom Tab or Browser.
     * @return true if the request to bind the service was successful, false if the service was already bound or it couldn't be bound.
     */
    public boolean bindServiceAndLaunchUri(@NonNull Uri uri) {
        this.nextUri = uri;
        boolean boundRequestSuccess = bindService();
        if (isBound || !boundRequestSuccess) {
            launchUri(uri);
        }
        return boundRequestSuccess;
    }

    /**
     * Opens a Uri in a Custom Tab or Browser
     *
     * @param uri the uri to open in a Custoam Tab or Browser.
     */
    public void launchUri(@NonNull Uri uri) {
        Context context = this.context.get();
        if (context == null) {
            Log.v(TAG, "Custom Tab Context was no longer valid.");
            return;
        }

        Log.d(TAG, "Launching uri..");
        final Intent intent = new CustomTabsIntent.Builder(session)
                .build()
                .intent;
        intent.addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
        intent.setData(uri);
        try {
            context.startActivity(intent);
        } catch (ActivityNotFoundException ignored) {
            Intent fallbackIntent = new Intent(Intent.ACTION_VIEW, uri);
            fallbackIntent.addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
            context.startActivity(fallbackIntent);
        }
    }

    /**
     * Query the OS for a Custom Tab compatible Browser application.
     * It will pick the default browser first if is Custom Tab compatible, then any Chrome browser or the first Custom Tab compatible browser.
     *
     * @param context a valid Context
     * @return the recommended Browser application package name, compatible with Custom Tabs if possible.
     */
    @VisibleForTesting
    static String getBestBrowserPackage(@NonNull Context context) {
        PackageManager pm = context.getPackageManager();
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.example.com"));
        ResolveInfo webHandler = pm.resolveActivity(browserIntent,
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PackageManager.MATCH_ALL : PackageManager.MATCH_DEFAULT_ONLY);
        String defaultBrowser = null;
        if (webHandler != null) {
            defaultBrowser = webHandler.activityInfo.packageName;
        }

        List<ResolveInfo> resolvedActivityList = pm.queryIntentActivities(browserIntent, 0);
        List<String> customTabsBrowsers = new ArrayList<>();
        for (ResolveInfo info : resolvedActivityList) {
            Intent serviceIntent = new Intent();
            serviceIntent.setAction(ACTION_CUSTOM_TABS_CONNECTION);
            serviceIntent.setPackage(info.activityInfo.packageName);
            if (pm.resolveService(serviceIntent, 0) != null) {
                customTabsBrowsers.add(info.activityInfo.packageName);
            }
        }
        if (customTabsBrowsers.contains(defaultBrowser)) {
            return defaultBrowser;
        } else if (customTabsBrowsers.contains(CHROME_STABLE)) {
            return CHROME_STABLE;
        } else if (customTabsBrowsers.contains(CHROME_SYSTEM)) {
            return CHROME_SYSTEM;
        } else if (customTabsBrowsers.contains(CHROME_BETA)) {
            return CHROME_BETA;
        } else if (customTabsBrowsers.contains(CHROME_DEV)) {
            return CHROME_DEV;
        } else if (!customTabsBrowsers.isEmpty()) {
            return customTabsBrowsers.get(0);
        } else {
            return defaultBrowser;
        }
    }

}