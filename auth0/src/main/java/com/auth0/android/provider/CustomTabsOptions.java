package com.auth0.android.provider;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import android.util.DisplayMetrics;

import androidx.annotation.ColorRes;
import androidx.annotation.Dimension;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.browser.customtabs.CustomTabColorSchemeParams;
import androidx.browser.customtabs.CustomTabsClient;
import androidx.browser.customtabs.CustomTabsIntent;
import androidx.browser.customtabs.CustomTabsSession;
import androidx.browser.trusted.TrustedWebActivityIntentBuilder;
import androidx.core.content.ContextCompat;

import com.auth0.android.annotation.ExperimentalAuth0Api;
import com.auth0.android.authentication.AuthenticationException;

import java.util.List;

/**
 * Holder for Custom Tabs customization options. Use {@link CustomTabsOptions#newBuilder()} to begin.
 */
public class CustomTabsOptions implements Parcelable {

    private static final String TAG = "CustomTabsOptions";

    private final boolean showTitle;
    @ColorRes
    private final int toolbarColor;
    private final BrowserPicker browserPicker;

    @Nullable
    private final List<String> disabledCustomTabsPackages;

    private final boolean ephemeralBrowsing;

    // Partial Custom Tabs - Bottom Sheet
    private final int initialHeight;
    private final int activityHeightResizeBehavior;
    private final int toolbarCornerRadius;

    // Partial Custom Tabs - Side Sheet
    private final int initialWidth;
    private final int sideSheetBreakpoint;

    // Partial Custom Tabs - Background Interaction
    private final boolean backgroundInteractionEnabled;

    private CustomTabsOptions(boolean showTitle, @ColorRes int toolbarColor, @NonNull BrowserPicker browserPicker,
                              @Nullable List<String> disabledCustomTabsPackages,
                              int initialHeight, int activityHeightResizeBehavior, int toolbarCornerRadius,
                              int initialWidth, int sideSheetBreakpoint,
                              boolean backgroundInteractionEnabled, boolean ephemeralBrowsing) {
        this.showTitle = showTitle;
        this.toolbarColor = toolbarColor;
        this.browserPicker = browserPicker;
        this.disabledCustomTabsPackages = disabledCustomTabsPackages;
        this.ephemeralBrowsing = ephemeralBrowsing;
        this.initialHeight = initialHeight;
        this.activityHeightResizeBehavior = activityHeightResizeBehavior;
        this.toolbarCornerRadius = toolbarCornerRadius;
        this.initialWidth = initialWidth;
        this.sideSheetBreakpoint = sideSheetBreakpoint;
        this.backgroundInteractionEnabled = backgroundInteractionEnabled;
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

    @NonNull
    CustomTabsOptions copyWithEphemeralBrowsing() {
        return new CustomTabsOptions(showTitle, toolbarColor, browserPicker,
            disabledCustomTabsPackages, initialHeight, activityHeightResizeBehavior, toolbarCornerRadius,
                initialWidth, sideSheetBreakpoint, backgroundInteractionEnabled, true);
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

        if (ephemeralBrowsing) {
            if (preferredPackage != null
                    && CustomTabsClient.isEphemeralBrowsingSupported(context, preferredPackage)) {
                builder.setEphemeralBrowsingEnabled(true);
            } else {
                Log.w(TAG, "Ephemeral browsing was requested but is not supported by the "
                        + "current browser (" + preferredPackage + "). "
                        + "Falling back to a regular Custom Tab.");
            }
        }

        if (toolbarColor > 0) {
            //Resource exists
            final CustomTabColorSchemeParams.Builder colorBuilder = new CustomTabColorSchemeParams.Builder()
                    .setToolbarColor(ContextCompat.getColor(context, toolbarColor));
            builder.setDefaultColorSchemeParams(colorBuilder.build());
        }

        // Partial Custom Tabs - Bottom Sheet
        if (initialHeight > 0) {
            builder.setInitialActivityHeightPx(dpToPx(context, initialHeight), activityHeightResizeBehavior);
        }
        if (toolbarCornerRadius > 0) {
            builder.setToolbarCornerRadiusDp(toolbarCornerRadius);
        }

        // Partial Custom Tabs - Side Sheet
        if (initialWidth > 0) {
            builder.setInitialActivityWidthPx(dpToPx(context, initialWidth));
        }
        if (sideSheetBreakpoint > 0) {
            builder.setActivitySideSheetBreakpointDp(sideSheetBreakpoint);
        }

        // Partial Custom Tabs - Background Interaction
        if (backgroundInteractionEnabled) {
            builder.setBackgroundInteractionEnabled(true);
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
        disabledCustomTabsPackages = in.createStringArrayList();
        ephemeralBrowsing = in.readByte() != 0;
        initialHeight = in.readInt();
        activityHeightResizeBehavior = in.readInt();
        toolbarCornerRadius = in.readInt();
        initialWidth = in.readInt();
        sideSheetBreakpoint = in.readInt();
        backgroundInteractionEnabled = in.readByte() != 0;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeByte((byte) (showTitle ? 1 : 0));
        dest.writeInt(toolbarColor);
        dest.writeParcelable(browserPicker, flags);
        dest.writeStringList(disabledCustomTabsPackages);
        dest.writeByte((byte) (ephemeralBrowsing ? 1 : 0));
        dest.writeInt(initialHeight);
        dest.writeInt(activityHeightResizeBehavior);
        dest.writeInt(toolbarCornerRadius);
        dest.writeInt(initialWidth);
        dest.writeInt(sideSheetBreakpoint);
        dest.writeByte((byte) (backgroundInteractionEnabled ? 1 : 0));
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

        @Nullable
        private List<String> disabledCustomTabsPackages;

        private boolean ephemeralBrowsing;

        private int initialHeight;
        private int activityHeightResizeBehavior;
        private int toolbarCornerRadius;
        private int initialWidth;
        private int sideSheetBreakpoint;
        private boolean backgroundInteractionEnabled;

        Builder() {
            this.showTitle = false;
            this.toolbarColor = 0;
            this.browserPicker = BrowserPicker.newBuilder().build();
            this.disabledCustomTabsPackages = null;
            this.ephemeralBrowsing = false;
            this.initialHeight = 0;
            this.activityHeightResizeBehavior = CustomTabsIntent.ACTIVITY_HEIGHT_DEFAULT;
            this.toolbarCornerRadius = 0;
            this.initialWidth = 0;
            this.sideSheetBreakpoint = 0;
            this.backgroundInteractionEnabled = false;
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
         * Enable ephemeral browsing for the Custom Tab.
         * When enabled, the Custom Tab runs in an isolated session — cookies, cache,
         * history, and credentials are deleted when the tab closes.
         * Requires Chrome 136+ or a compatible browser. On unsupported browsers,
         * a warning is logged and a regular Custom Tab is used instead.
         * By default, ephemeral browsing is disabled.
         *
         * <p><b>Warning:</b> Ephemeral browsing support in Auth0.Android is still experimental
         * and can change in the future. Please test it thoroughly in all the targeted browsers
         * and OS variants and let us know your feedback.</p>
         *
         * @return this same builder instance.
         */
        @ExperimentalAuth0Api
        @NonNull
        public Builder withEphemeralBrowsing() {
            this.ephemeralBrowsing = true;
            return this;
        }

        /**
         * Sets the initial height for the Custom Tab to display as a bottom sheet.
         * When set, the Custom Tab will appear as a bottom sheet instead of full screen.
         * Pass the size in dp; it will be converted to pixels internally.
         * The minimum height enforced by Chrome is 50% of the screen; values below this are auto-adjusted.
         * Falls back to full screen on browsers that don't support Partial Custom Tabs (requires Chrome 107+).
         * By default, the bottom sheet is resizable by the user. Use {@link #withResizable(boolean)}
         * to lock the height.
         *
         * @param height the initial bottom sheet height in dp.
         * @return this same builder instance.
         */
        @NonNull
        public Builder withInitialHeight(@Dimension(unit = Dimension.DP) int height) {
            this.initialHeight = height;
            return this;
        }

        /**
         * Sets whether the user can resize the Partial Custom Tab by dragging.
         * For bottom sheets, this controls whether the user can drag the toolbar handle to
         * expand or collapse the sheet. For side sheets, this controls whether the sheet
         * can be resized. By default, the Partial Custom Tab is resizable.
         * Pass {@code false} to lock the size. Only takes effect when
         * {@link #withInitialHeight(int)} is also set.
         *
         * @param resizable whether the Partial Custom Tab should be resizable.
         * @return this same builder instance.
         */
        @NonNull
        public Builder withResizable(boolean resizable) {
            this.activityHeightResizeBehavior = resizable
                    ? CustomTabsIntent.ACTIVITY_HEIGHT_ADJUSTABLE
                    : CustomTabsIntent.ACTIVITY_HEIGHT_FIXED;
            return this;
        }

        /**
         * Sets the toolbar's top corner radii in dp. Only takes effect when the Custom Tab is
         * displayed as a bottom sheet (i.e., when {@link #withInitialHeight(int)} is also set).
         * Pass the size in dp. The underlying
         * {@link CustomTabsIntent.Builder#setToolbarCornerRadiusDp(int)} only accepts values in
         * the range {@code 0}&ndash;{@code 16} (inclusive); to avoid a runtime crash, values
         * outside that range are clamped: negative values are treated as {@code 0} and values
         * greater than {@code 16} are capped to {@code 16}.
         *
         * @param cornerRadius the toolbar's top corner radius in dp. Clamped to {@code [0, 16]}.
         * @return this same builder instance.
         */
        @NonNull
        public Builder withToolbarCornerRadius(@Dimension(unit = Dimension.DP) int cornerRadius) {
            if (cornerRadius < 0) {
                cornerRadius = 0;
            }
            if (cornerRadius > 16) {
                cornerRadius = 16;
            }
            this.toolbarCornerRadius = cornerRadius;
            return this;
        }

        /**
         * Sets the initial width for the Custom Tab to display as a side sheet on larger screens.
         * The Custom Tab will behave as a side sheet only if the screen's width is bigger than
         * the breakpoint value set by {@link #withSideSheetBreakpoint(int)}. If no breakpoint is
         * explicitly set, the browser's default breakpoint (typically 840dp in Chrome) is used,
         * so smaller-width devices will continue to render as a bottom sheet or full screen
         * rather than as a side sheet.
         * Pass the size in dp; it will be converted to pixels internally.
         * Falls back to bottom sheet or full screen on unsupported browsers.
         *
         * @param width the initial side sheet width in dp.
         * @return this same builder instance.
         */
        @NonNull
        public Builder withInitialWidth(@Dimension(unit = Dimension.DP) int width) {
            this.initialWidth = width;
            return this;
        }

        /**
         * Sets the breakpoint in dp to switch between bottom sheet and side sheet mode.
         * If the screen's width is bigger than this value, the Custom Tab will behave as a side sheet;
         * otherwise it will behave as a bottom sheet.
         * <p>
         * When this method is not called (or the value is left at the default {@code 0}), the
         * breakpoint is <b>not</b> overridden and the browser's built-in default (typically
         * {@code 840dp} in Chrome) is applied. This means devices with a screen width smaller
         * than the browser default will still render as a bottom sheet, not a side sheet.
         *
         * @param breakpoint the breakpoint in dp.
         * @return this same builder instance.
         */
        @NonNull
        public Builder withSideSheetBreakpoint(@Dimension(unit = Dimension.DP) int breakpoint) {
            this.sideSheetBreakpoint = breakpoint;
            return this;
        }

        /**
         * Enables or disables interaction with the background app when a Partial Custom Tab is displayed.
         * By default, background interaction is disabled.
         *
         * @param enabled whether to enable interaction with the app behind the partial tab.
         * @return this same builder instance.
         */
        @NonNull
        public Builder withBackgroundInteractionEnabled(boolean enabled) {
            this.backgroundInteractionEnabled = enabled;
            return this;
        }

        /**
         * Create a new CustomTabsOptions instance with the customization settings.
         *
         * @return an instance of CustomTabsOptions with the customization settings.
         */
        @NonNull
        public CustomTabsOptions build() {
            return new CustomTabsOptions(showTitle, toolbarColor, browserPicker, disabledCustomTabsPackages,
                    initialHeight, activityHeightResizeBehavior, toolbarCornerRadius,
                    initialWidth, sideSheetBreakpoint, backgroundInteractionEnabled, ephemeralBrowsing);
        }
    }
    private int dpToPx(@NonNull Context context, int dp) {
        final DisplayMetrics metrics = context.getResources().getDisplayMetrics();
        return Math.round(dp * metrics.density);
    }

}
