package com.auth0.android.provider;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.ColorRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.browser.customtabs.CustomTabColorSchemeParams;
import androidx.browser.customtabs.CustomTabsIntent;
import androidx.browser.customtabs.CustomTabsSession;
import androidx.browser.trusted.TrustedWebActivityIntentBuilder;
import androidx.core.content.ContextCompat;

import com.auth0.android.authentication.AuthenticationException;

import java.util.List;

/**
 * Holder for Custom Tabs customization options. Use {@link CustomTabsOptions#newBuilder()} to begin.
 */
public class CustomTabsOptions implements Parcelable {

    private final boolean showTitle;
    @ColorRes
    private final int toolbarColor;
    private final BrowserPicker browserPicker;
    private final boolean ephemeralBrowsingEnabled;

    @Nullable
    private final List<String> disabledCustomTabsPackages;

    private CustomTabsOptions(boolean showTitle, @ColorRes int toolbarColor, @NonNull BrowserPicker browserPicker, boolean ephemeralBrowsingEnabled, @Nullable List<String> disabledCustomTabsPackages) {
        this.showTitle = showTitle;
        this.toolbarColor = toolbarColor;
        this.browserPicker = browserPicker;
        this.ephemeralBrowsingEnabled = ephemeralBrowsingEnabled;
        this.disabledCustomTabsPackages = disabledCustomTabsPackages;
    }

    @Nullable
    String getPreferredPackage(@NonNull PackageManager pm) {
        return browserPicker.getBestBrowserPackage(pm);
    }

    boolean hasCompatibleBrowser(@NonNull PackageManager pm) {
        return getPreferredPackage(pm) != null;
    }

    /**
     * Returns whether the browser preferred package has custom tab disabled or not.
     *
     * @param preferredPackage the preferred browser package name.
     * @return whether the browser preferred package has custom tab disabled or not.
     */
    boolean isDisabledCustomTabBrowser(@NonNull String preferredPackage) {
        return disabledCustomTabsPackages != null && disabledCustomTabsPackages.contains(preferredPackage);
    }

    /**
     * Create a new CustomTabsOptions.Builder instance.
     *
     * @return a new CustomTabsOptions.Builder ready to customize.
     */
    @NonNull
    public static Builder newBuilder() {
        return new Builder();
    }


    @SuppressLint("ResourceType")
    Intent toIntent(@NonNull Context context, @Nullable CustomTabsSession session) {
        String preferredPackage = this.getPreferredPackage(context.getPackageManager());

        if (preferredPackage != null && this.isDisabledCustomTabBrowser(preferredPackage)) {
            return new Intent(Intent.ACTION_VIEW);
        }

        final CustomTabsIntent.Builder builder = new CustomTabsIntent.Builder(session)
                .setShowTitle(showTitle)
                .setShareState(CustomTabsIntent.SHARE_STATE_OFF);
        if (toolbarColor > 0) {
            //Resource exists
            final CustomTabColorSchemeParams.Builder colorBuilder = new CustomTabColorSchemeParams.Builder()
                    .setToolbarColor(ContextCompat.getColor(context, toolbarColor));
            builder.setDefaultColorSchemeParams(colorBuilder.build());
        }
        if (ephemeralBrowsingEnabled) {
            builder.setEphemeralBrowsingEnabled(true);
        }
        return builder.build().intent;
    }

    @SuppressLint("ResourceType")
    TrustedWebActivityIntentBuilder toTwaIntentBuilder(@NonNull Context context, @NonNull Uri uri) {
        TrustedWebActivityIntentBuilder builder = new TrustedWebActivityIntentBuilder(uri);
        if (toolbarColor > 0) {
            //Resource exists
            final CustomTabColorSchemeParams.Builder colorBuilder = new CustomTabColorSchemeParams.Builder()
                    .setToolbarColor(ContextCompat.getColor(context, toolbarColor));
            builder.setDefaultColorSchemeParams(colorBuilder.build());
        }
        return builder;
    }

    protected CustomTabsOptions(@NonNull Parcel in) {
        showTitle = in.readByte() != 0;
        toolbarColor = in.readInt();
        browserPicker = in.readParcelable(BrowserPicker.class.getClassLoader());
        ephemeralBrowsingEnabled = in.readByte() != 0;
        disabledCustomTabsPackages = in.createStringArrayList();
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeByte((byte) (showTitle ? 1 : 0));
        dest.writeInt(toolbarColor);
        dest.writeParcelable(browserPicker, flags);
        dest.writeByte((byte) (ephemeralBrowsingEnabled ? 1 : 0));
        dest.writeStringList(disabledCustomTabsPackages);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<CustomTabsOptions> CREATOR = new Creator<CustomTabsOptions>() {
        @Override
        public CustomTabsOptions createFromParcel(Parcel in) {
            return new CustomTabsOptions(in);
        }

        @Override
        public CustomTabsOptions[] newArray(int size) {
            return new CustomTabsOptions[size];
        }
    };


    @SuppressWarnings("WeakerAccess")
    public static class Builder {
        @ColorRes
        private int toolbarColor;
        private boolean showTitle;
        private boolean ephemeralBrowsingEnabled;
        @NonNull
        private BrowserPicker browserPicker;

        @Nullable
        private List<String> disabledCustomTabsPackages;

        Builder() {
            this.showTitle = false;
            this.toolbarColor = 0;
            this.ephemeralBrowsingEnabled = false;
            this.browserPicker = BrowserPicker.newBuilder().build();
            this.disabledCustomTabsPackages = null;
        }

        /**
         * Change the Custom Tab toolbar color to the given one.
         *
         * @param toolbarColor the new toolbar color to set
         * @return this same builder instance.
         */
        @NonNull
        public Builder withToolbarColor(@ColorRes int toolbarColor) {
            this.toolbarColor = toolbarColor;
            return this;
        }

        /**
         * Whether to make the Custom Tab show the Page Title in the toolbar or not.
         * By default, the Page Title will be hidden.
         *
         * @param showTitle whether to show the Page Title in the toolbar or not.
         * @return this same builder instance.
         */
        @NonNull
        public Builder showTitle(boolean showTitle) {
            this.showTitle = showTitle;
            return this;
        }

        /**
         * Whether to enable ephemeral browsing for the Custom Tab session.
         * When enabled, the Custom Tab session will not persist browsing data, cookies, or history.
         * By default, ephemeral browsing is disabled.
         *
         * @param ephemeralBrowsingEnabled whether to enable ephemeral browsing or not.
         * @return this same builder instance.
         */
        @NonNull
        public Builder withEphemeralBrowsingEnabled(boolean ephemeralBrowsingEnabled) {
            this.ephemeralBrowsingEnabled = ephemeralBrowsingEnabled;
            return this;
        }

        /**
         * Filter the browser applications to launch the authentication on.
         * <p>
         * WARNING: The browser application in which the intent is resolved is chosen automatically
         * for you considering the device's default browser app and the browsers that are Custom Tabs
         * compatible. Overriding this preference is not only a bad practice, but can also result
         * in an unexpected behavior that could prevent your users from authenticating successfully.
         * That said, it might help resolve some browser UX or incompatibility issues when used
         * in combination with "Android App Links". Use it at your own risk.
         *
         * @param browserPicker the browser picker to use.
         * @return the current builder instance
         * @see AuthenticationException#isBrowserAppNotAvailable()
         */
        @NonNull
        public Builder withBrowserPicker(@NonNull BrowserPicker browserPicker) {
            this.browserPicker = browserPicker;
            return this;
        }

        /**
         * Define a list of browser packages that disables the launching of authentication on custom tabs.
         * The authentication url will launch on the preferred package external browser.
         *
         * @param disabledCustomTabsPackages list of browser packages.
         * @return the current builder instance
         */
        @NonNull
        public Builder withDisabledCustomTabsPackages(List<String> disabledCustomTabsPackages) {
            this.disabledCustomTabsPackages = disabledCustomTabsPackages;
            return this;
        }

        /**
         * Create a new CustomTabsOptions instance with the customization settings.
         *
         * @return an instance of CustomTabsOptions with the customization settings.
         */
        @NonNull
        public CustomTabsOptions build() {
            return new CustomTabsOptions(showTitle, toolbarColor, browserPicker, ephemeralBrowsingEnabled, disabledCustomTabsPackages);
        }
    }

}
