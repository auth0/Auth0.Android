package com.auth0.android.provider;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static android.support.customtabs.CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION;

public class BrowserPicker implements Parcelable {

    @NonNull
    private static final List<String> CHROME_BROWSERS = Arrays.asList(
            "com.android.chrome", //STABLE
            "com.google.android.apps.chrome", //SYSTEM
            "com.android.chrome.beta", //BETA
            "com.android.chrome.dev" //DEV
    );
    @Nullable
    private final List<String> allowedPackages;

    private BrowserPicker(@Nullable List<String> allowedPackages) {
        this.allowedPackages = allowedPackages;
    }

    protected BrowserPicker(@NonNull Parcel in) {
        allowedPackages = in.createStringArrayList();
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeStringList(allowedPackages);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<BrowserPicker> CREATOR = new Creator<BrowserPicker>() {
        @Override
        public BrowserPicker createFromParcel(Parcel in) {
            return new BrowserPicker(in);
        }

        @Override
        public BrowserPicker[] newArray(int size) {
            return new BrowserPicker[size];
        }
    };

    /**
     * Create a new BrowserPicker.Builder instance.
     *
     * @return a new BrowserPicker.Builder ready to customize.
     */
    @NonNull
    public static BrowserPicker.Builder newBuilder() {
        return new BrowserPicker.Builder();
    }

    public static class Builder {
        private List<String> allowedPackages;

        private Builder() {
        }

        //TODO: JAVADOCS
        @NonNull
        public Builder withAllowedPackages(@NonNull List<String> allowedPackages) {
            this.allowedPackages = allowedPackages;
            return this;
        }

        @NonNull
        public BrowserPicker build() {
            return new BrowserPicker(allowedPackages);
        }

    }

    @Nullable
    String getBestBrowserPackage(@NonNull PackageManager pm) {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.example.com"));
        ResolveInfo webHandler = pm.resolveActivity(browserIntent,
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PackageManager.MATCH_ALL : PackageManager.MATCH_DEFAULT_ONLY);
        String defaultBrowser = null;
        if (webHandler != null) {
            defaultBrowser = webHandler.activityInfo.packageName;
        }

        final List<ResolveInfo> availableBrowsers = pm.queryIntentActivities(browserIntent, 0);
        final List<String> regularBrowsers = new ArrayList<>();
        final List<String> customTabsBrowsers = new ArrayList<>();
        final boolean isFilterEnabled = allowedPackages != null;

        for (ResolveInfo info : availableBrowsers) {
            boolean isAllowed = !isFilterEnabled || allowedPackages.contains(info.activityInfo.packageName);
            if (!isAllowed) {
                continue;
            }
            Intent serviceIntent = new Intent();
            serviceIntent.setAction(ACTION_CUSTOM_TABS_CONNECTION);
            serviceIntent.setPackage(info.activityInfo.packageName);
            if (pm.resolveService(serviceIntent, 0) != null) {
                customTabsBrowsers.add(info.activityInfo.packageName);
            } else {
                regularBrowsers.add(info.activityInfo.packageName);
            }
        }

        //If the browser packages were filtered, use the allowed packages list as preference.
        //A user-selected default browser will always be picked up first.
        List<String> preferenceList = isFilterEnabled ? allowedPackages : CHROME_BROWSERS;

        //If the list was filtered, the customTabsBrowsers and regularBrowsers Lists will contain only allowed packages.
        final String customTabBrowser = getFirstMatch(customTabsBrowsers, preferenceList, defaultBrowser);
        if (customTabBrowser != null) {
            //Will return a custom tab compatible browser.
            return customTabBrowser;
        }

        //Will return any browser or null
        return getFirstMatch(regularBrowsers, preferenceList, defaultBrowser);
    }

    @Nullable
    private String getFirstMatch(@NonNull List<String> baseList, @NonNull List<String> preferenceList, @Nullable String bestChoice) {
        if (bestChoice != null && preferenceList.contains(bestChoice) && baseList.contains(bestChoice)) {
            return bestChoice;
        }
        //Walk the preferred items
        for (String b : preferenceList) {
            if (baseList.contains(b)) {
                return b;
            }
        }
        //Fallback to the first available item
        if (!baseList.isEmpty()) {
            return baseList.get(0);
        }
        return null;
    }
}
