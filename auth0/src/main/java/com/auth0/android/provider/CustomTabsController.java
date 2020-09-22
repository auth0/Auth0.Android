package com.auth0.android.provider;

import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.VisibleForTesting;
import android.support.customtabs.CustomTabsClient;
import android.support.customtabs.CustomTabsServiceConnection;
import android.support.customtabs.CustomTabsSession;
import android.util.Log;

import java.lang.ref.WeakReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@SuppressWarnings("WeakerAccess")
class CustomTabsController extends CustomTabsServiceConnection {

    static final String TAG = CustomTabsController.class.getSimpleName();
    private static final long MAX_WAIT_TIME_SECONDS = 1;

    private final WeakReference<Context> context;
    private final AtomicReference<CustomTabsSession> session;
    private final CountDownLatch sessionLatch;
    private final String preferredPackage;

    @NonNull
    private CustomTabsOptions customTabsOptions;
    private boolean isBound;

    @VisibleForTesting
    CustomTabsController(@NonNull Context context, @NonNull CustomTabsOptions options) {
        this.context = new WeakReference<>(context);
        this.session = new AtomicReference<>();
        this.sessionLatch = new CountDownLatch(1);
        this.customTabsOptions = options;
        this.preferredPackage = options.getPreferredPackage(context.getPackageManager());
    }

    @VisibleForTesting
    void clearContext() {
        this.context.clear();
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

}