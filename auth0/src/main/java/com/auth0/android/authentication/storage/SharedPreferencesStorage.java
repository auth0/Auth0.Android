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
    public void store(@NonNull String name, @Nullable Long value) {
        if (value == null) {
            sp.edit().remove(name).apply();
        } else {
            sp.edit().putLong(name, value).apply();
        }
    }

    @Override
    public void store(@NonNull String name, @Nullable Integer value) {
        if (value == null) {
            sp.edit().remove(name).apply();
        } else {
            sp.edit().putInt(name, value).apply();
        }
    }

    @Override
    public void store(@NonNull String name, @Nullable String value) {
        if (value == null) {
            sp.edit().remove(name).apply();
        } else {
            sp.edit().putString(name, value).apply();
        }
    }

    @Nullable
    @Override
    public Long retrieveLong(@NonNull String name) {
        if (!sp.contains(name)) {
            return null;
        }
        return sp.getLong(name, 0);
    }

    @Nullable
    @Override
    public String retrieveString(@NonNull String name) {
        if (!sp.contains(name)) {
            return null;
        }
        return sp.getString(name, null);
    }

    @Nullable
    @Override
    public Integer retrieveInteger(@NonNull String name) {
        if (!sp.contains(name)) {
            return null;
        }
        return sp.getInt(name, 0);
    }
}
