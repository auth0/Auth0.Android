package com.auth0.android.authentication.storage;


import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;

/**
 * An implementation of {@link Storage} that uses {@link android.content.SharedPreferences} in Context.MODE_PRIVATE to store the values.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class SharedPreferencesStorage implements Storage {

    private static final String SHARED_PREFERENCES_NAME = "com.auth0.authentication.storage";

    private final SharedPreferences sp;

    /**
     * Creates a new {@link Storage} that uses {@link SharedPreferences} in Context.MODE_PRIVATE to store values.
     *
     * @param context a valid context
     */
    public SharedPreferencesStorage(@NonNull Context context) {
        this(context, SHARED_PREFERENCES_NAME);
    }

    /**
     * Creates a new {@link Storage} that uses {@link SharedPreferences} in Context.MODE_PRIVATE to store values.
     *
     * @param context               a valid context
     * @param sharedPreferencesName the preferences file name
     */
    public SharedPreferencesStorage(@NonNull Context context, @NonNull String sharedPreferencesName) {
        if (TextUtils.isEmpty(sharedPreferencesName)) {
            throw new IllegalArgumentException("The SharedPreferences name is invalid.");
        }
        sp = context.getSharedPreferences(sharedPreferencesName, Context.MODE_PRIVATE);
    }

    @Override
    public void store(@NonNull String name, @Nullable String value) {
        sp.edit().putString(name, value).apply();
    }

    @Nullable
    @Override
    public String retrieve(@NonNull String name) {
        return sp.getString(name, null);
    }
}
