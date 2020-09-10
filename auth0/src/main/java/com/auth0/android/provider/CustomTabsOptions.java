package com.auth0.android.provider;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.annotation.ColorRes;
import android.support.annotation.NonNull;
import android.support.customtabs.CustomTabsIntent;
import android.support.customtabs.CustomTabsSession;
import android.support.v4.content.ContextCompat;

/**
 * Holder for Custom Tabs customization options. Use {@link CustomTabsOptions#newBuilder()} to begin.
 */
public class CustomTabsOptions implements Parcelable {

    private final boolean showTitle;
    @ColorRes
    private final int toolbarColor;

    private CustomTabsOptions(boolean showTitle, @ColorRes int toolbarColor) {
        this.showTitle = showTitle;
        this.toolbarColor = toolbarColor;
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
    Intent toIntent(Context context, CustomTabsSession session) {
        final CustomTabsIntent.Builder builder = new CustomTabsIntent.Builder(session)
                .setShowTitle(showTitle);
        if (toolbarColor > 0) {
            //Resource exists
            builder.setToolbarColor(ContextCompat.getColor(context, toolbarColor));
        }
        return builder.build().intent;
    }


    protected CustomTabsOptions(@NonNull Parcel in) {
        showTitle = in.readByte() != 0x00;
        toolbarColor = in.readInt();
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        dest.writeByte((byte) (showTitle ? 0x01 : 0x00));
        dest.writeInt(toolbarColor);
    }

    @SuppressWarnings("unused")
    public static final Parcelable.Creator<CustomTabsOptions> CREATOR = new Parcelable.Creator<CustomTabsOptions>() {
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

        Builder() {
            this.showTitle = false;
            this.toolbarColor = 0;
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
         * Create a new CustomTabsOptions instance with the customization settings.
         *
         * @return an instance of CustomTabsOptions with the customization settings.
         */
        @NonNull
        public CustomTabsOptions build() {
            return new CustomTabsOptions(showTitle, toolbarColor);
        }
    }

}
