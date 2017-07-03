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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@SuppressWarnings("WeakerAccess")
class CustomTabsController extends CustomTabsServiceConnection {

    private static final String TAG = CustomTabsController.class.getSimpleName();
    private static final long MAX_WAIT_TIME_SECONDS = 1;
    private static final String ACTION_CUSTOM_TABS_CONNECTION = "android.support.customtabs.action.CustomTabsService";
    //Known Browsers
    private static final String CHROME_STABLE = "com.android.chrome";
    private static final String CHROME_SYSTEM = "com.google.android.apps.chrome";
    private static final String CHROME_BETA = "com.android.chrome.beta";
    private static final String CHROME_DEV = "com.android.chrome.dev";

    private final WeakReference<Context> context;
    private final AtomicReference<CustomTabsSession> session;
    private final CountDownLatch sessionLatch;
    private final String preferredPackage;


    @VisibleForTesting
    CustomTabsController(@NonNull Context context, @NonNull String browserPackage) {
        this.context = new WeakReference<>(context);
        this.session = new AtomicReference<>();
        this.sessionLatch = new CountDownLatch(1);
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
        if (customTabsClient == null) {
            return;
        }
        Log.d(TAG, "CustomTabs Service connected");
        customTabsClient.warmup(0L);
        session.set(customTabsClient.newSession(null));
        sessionLatch.countDown();
    }

    @Override
    public void onServiceDisconnected(ComponentName componentName) {
        Log.d(TAG, "CustomTabs Service disconnected");
        session.set(null);
    }

    /**
     * Attempts to bind the Custom Tabs Service to the Context.
     */
    public void bindService() {
        Log.v(TAG, "Trying to bind the service");
        Context context = this.context.get();
        boolean success = false;
        if (context != null) {
            success = CustomTabsClient.bindCustomTabsService(context, preferredPackage, this);
        }
        Log.v(TAG, "Bind request result: " + success);
    }

    /**
     * Attempts to unbind the Custom Tabs Service from the Context.
     */
    public void unbindService() {
        Log.v(TAG, "Trying to unbind the service");
        Context context = this.context.get();
        if (context != null) {
            context.unbindService(this);
        }
    }

    /**
     * Opens a Uri in a Custom Tab or Browser.
     * The Custom Tab service will be given up to {@link CustomTabsController#MAX_WAIT_TIME_SECONDS} to be connected.
     * If it fails to connect the Uri will be opened on a Browser.
     *
     * @param uri the uri to open in a Custom Tab or Browser.
     */
    public void launchUri(@NonNull final Uri uri) {
        final Context context = this.context.get();
        if (context == null) {
            Log.v(TAG, "Custom Tab Context was no longer valid.");
            return;
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                boolean available = false;
                try {
                    available = sessionLatch.await(MAX_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
                Log.d(TAG, "Launching URI. Custom Tabs available: " + available);

                final Intent intent = new CustomTabsIntent.Builder(session.get())
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
        }).start();
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