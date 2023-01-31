package com.auth0.android.provider;

import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import androidx.browser.customtabs.CustomTabsClient;
import androidx.browser.customtabs.CustomTabsServiceConnection;
import androidx.browser.customtabs.CustomTabsSession;

import com.google.androidbrowserhelper.trusted.TwaLauncher;

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
    private final TwaLauncher twaLauncher;

    @NonNull
    private final CustomTabsOptions customTabsOptions;
    private boolean didTryToBind;
    private boolean launchedAsTwa;

    @VisibleForTesting
    CustomTabsController(@NonNull Context context, @NonNull CustomTabsOptions options) {
        this.context = new WeakReference<>(context);
        this.session = new AtomicReference<>();
        this.sessionLatch = new CountDownLatch(1);
        this.customTabsOptions = options;
        this.preferredPackage = options.getPreferredPackage(context.getPackageManager());
        this.twaLauncher  = new TwaLauncher(context);
    }

    @VisibleForTesting
    void clearContext() {
        this.context.clear();
    }

    @Override
    public void onCustomTabsServiceConnected(@NonNull ComponentName componentName, @NonNull CustomTabsClient customTabsClient) {
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
        didTryToBind = false;
        boolean wasBound = false;
        if (context != null && preferredPackage != null) {
            didTryToBind = true;
            wasBound = CustomTabsClient.bindCustomTabsService(context, preferredPackage, this);
        }
        Log.v(TAG, String.format("Bind request result (%s): %s", preferredPackage, wasBound));
    }

    /**
     * Attempts to unbind the Custom Tabs Service from the Context.
     */
    public void unbindService() {
        Log.v(TAG, "Trying to unbind the service");
        Context context = this.context.get();
        if (didTryToBind && context != null) {
            context.unbindService(this);
            didTryToBind = false;
        }
        if(launchedAsTwa) {
            twaLauncher.destroy();
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
    public void launchUri(@NonNull final Uri uri, @NonNull final boolean launchAsTwa) {
        final Context context = this.context.get();
        if (context == null) {
            Log.v(TAG, "Custom Tab Context was no longer valid.");
            return;
        }

        new Thread(() -> {
            try {
                if (launchAsTwa) {
                    launchedAsTwa = true;
                    twaLauncher.launch(
                            customTabsOptions.toTwaIntent(context, uri),
                            null,
                            null,
                            null,
                            TwaLauncher.CCT_FALLBACK_STRATEGY
                    );
                } else {
                    launchAsDefault(context, uri);
                }
            } catch (ActivityNotFoundException ex) {
                Log.e(TAG, "Could not find any Browser application installed in this device to handle the intent.");
            }
        }).start();
    }

    private void launchAsDefault(Context context, Uri uri) {
        bindService();
        boolean available = false;
        try {
            available = sessionLatch.await(preferredPackage == null ? 0 : MAX_WAIT_TIME_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }
        Log.d(TAG, "Launching URI. Custom Tabs available: " + available);
        final Intent intent = customTabsOptions.toIntent(context, session.get());
        intent.setData(uri);
        context.startActivity(intent);
    }

}