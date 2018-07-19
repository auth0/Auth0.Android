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
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.support.customtabs.CustomTabsClient;
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
    //Known Browsers with Custom Tabs support
    private static final String CHROME_STABLE = "com.android.chrome";
    private static final String CHROME_SYSTEM = "com.google.android.apps.chrome";
    private static final String CHROME_BETA = "com.android.chrome.beta";
    private static final String CHROME_DEV = "com.android.chrome.dev";

    private final WeakReference<Context> context;
    private final AtomicReference<CustomTabsSession> session;
    private final CountDownLatch sessionLatch;
    private final String preferredPackage;

    @Nullable
    private CustomTabsOptions customTabsOptions;
    private boolean isBound;

    @VisibleForTesting
    CustomTabsController(@NonNull Context context, @Nullable String browserPackage) {
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

    void setCustomizationOptions(@Nullable CustomTabsOptions options) {
        this.customTabsOptions = options;
    }

    @VisibleForTesting
    CustomTabsOptions getCustomizationOptions() {
        return this.customTabsOptions;
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
        isBound = false;
        if (context != null && preferredPackage != null) {
            isBound = CustomTabsClient.bindCustomTabsService(context, preferredPackage, this);
        }
        Log.v(TAG, "Bind request result: " + isBound);
    }

    /**
     * Attempts to unbind the Custom Tabs Service from the Context.
     */
    public void unbindService() {
        Log.v(TAG, "Trying to unbind the service");
        Context context = this.context.get();
        if (isBound && context != null) {
            context.unbindService(this);
            isBound = false;
        }
    }

    /**
     * Opens a Uri in a Custom Tab or Browser.
     * The Custom Tab service will be given up to {@link CustomTabsController#MAX_WAIT_TIME_SECONDS} to be connected.
     * If it fails to connect the Uri will be opened on a Browser.
     * <p>
     * In the exceptional case that no Browser app is installed on the device, this method will fail silently and do nothing.
     * Please, ensure the {@link Intent#ACTION_VIEW} action can be handled before calling this method.
     *
     * @param uri the uri to open in a Custom Tab or Browser.
     */
    public void launchUri(@NonNull final Uri uri) {
        final Context context = this.context.get();
        if (context == null) {
            Log.v(TAG, "Custom Tab Context was no longer valid.");
            return;
        }

        if (customTabsOptions == null) {
            customTabsOptions = CustomTabsOptions.newBuilder().build();
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                boolean available = false;
                try {
                    available = sessionLatch.await(preferredPackage == null ? 0 : MAX_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
                Log.d(TAG, "Launching URI. Custom Tabs available: " + available);

                final Intent intent = customTabsOptions.toIntent(context, session.get());
                intent.setData(uri);
                try {
                    context.startActivity(intent);
                } catch (ActivityNotFoundException ex) {
                    Log.e(TAG, "Could not find any Browser application installed in this device to handle the intent.");
                }
            }
        }).start();
    }

    /**
     * Query the OS for a Custom Tab compatible Browser application.
     * It will pick the default browser first if is Custom Tab compatible, then any Chrome browser or the first Custom Tab compatible browser.
     *
     * @param context a valid Context
     * @return the recommended Browser application package name, compatible with Custom Tabs. Null if no compatible browser is found.
     */
    @Nullable
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
            return null;
        }
    }
}