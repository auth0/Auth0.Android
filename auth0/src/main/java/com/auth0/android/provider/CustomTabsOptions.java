package com.auth0.android.provider;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.ColorRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.browser.customtabs.CustomTabsIntent;
import androidx.browser.customtabs.CustomTabsSession;
import androidx.core.content.ContextCompat;

import com.auth0.android.authentication.AuthenticationException;

/**
 * Holder for Custom Tabs customization options. Use {@link CustomTabsOptions#newBuilder()} to begin.
 */
public class CustomTabsOptions implements Parcelable {

    private final boolean showTitle;
    @ColorRes
    private final int toolbarColor;
    private final BrowserPicker browserPicker;

    private CustomTabsOptions(boolean showTitle, @ColorRes int toolbarColor, @NonNull BrowserPicker browserPicker) {
        this.showTitle = showTitle;
        this.toolbarColor = toolbarColor;
        this.browserPicker = browserPicker;
    }

    @Nullable
    String getPreferredPackage(@NonNull PackageManager pm) {
        return browserPicker.getBestBrowserPackage(pm);
    }

    boolean hasCompatibleBrowser(@NonNull PackageManager pm) {
        return getPreferredPackage(pm) != null;
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
        final CustomTabsIntent.Builder builder = new CustomTabsIntent.Builder(session)
                .setShowTitle(showTitle);
        if (toolbarColor > 0) {
            //Resource exists
            builder.setToolbarColor(ContextCompat.getColor(context, toolbarColor));
        }
        return builder.build().intent;
    }

    protected CustomTabsOptions(@NonNull Parcel in) {
        showTitle = in.readByte() != 0;
        toolbarColor = in.readInt();
        browserPicker = in.readParcelable(BrowserPicker.class.getClassLoader());
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeByte((byte) (showTitle ? 1 : 0));
        dest.writeInt(toolbarColor);
        dest.writeParcelable(browserPicker, flags);
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
        @NonNull
        private BrowserPicker browserPicker;

        Builder() {
            this.showTitle = false;
            this.toolbarColor = 0;
            this.browserPicker = BrowserPicker.newBuilder().build();
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
         * Create a new CustomTabsOptions instance with the customization settings.
         *
         * @return an instance of CustomTabsOptions with the customization settings.
         */
        @NonNull
        public CustomTabsOptions build() {
            return new CustomTabsOptions(showTitle, toolbarColor, browserPicker);
        }
    }

}
