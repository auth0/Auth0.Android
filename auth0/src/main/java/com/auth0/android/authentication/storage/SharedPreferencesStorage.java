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

    /**
     * Store a given value in the Storage.
     * Supported value types are: {@link String}, {@link Boolean}, {@link Long}, {@link Float} and {@link Integer}.
     *
     * @param name   the name of the value to store.
     * @param value  the value to store. Can be null.
     * @param tClazz the class of the value to store.
     * @param <T>    the type of the value to store.
     * @throws IllegalArgumentException if the given class type is not supported
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T> void store(@NonNull String name, @Nullable T value, @NonNull Class<T> tClazz) throws IllegalArgumentException {
        if (value == null) {
            sp.edit().remove(name).apply();
        } else if (tClazz.isAssignableFrom(String.class)) {
            sp.edit().putString(name, (String) value).apply();
        } else if (tClazz.isAssignableFrom(Boolean.class)) {
            sp.edit().putBoolean(name, (Boolean) value).apply();
        } else if (tClazz.isAssignableFrom(Long.class)) {
            sp.edit().putLong(name, (Long) value).apply();
        } else if (tClazz.isAssignableFrom(Float.class)) {
            sp.edit().putFloat(name, (Float) value).apply();
        } else if (tClazz.isAssignableFrom(Integer.class)) {
            sp.edit().putInt(name, (Integer) value).apply();
        } else {
            throw new IllegalArgumentException("The class type is not supported. Supported types are: String, Boolean, Long, Float and Integer.");
        }
    }

    /**
     * Retrieve a value from the Storage.
     * Supported value types are: {@link String}, {@link Boolean}, {@link Long}, {@link Float} and {@link Integer}.
     *
     * @param name   the name of the value to retrieve.
     * @param tClazz the class of the value to retrieve.
     * @param <T>    the type of the value to retrieve.
     * @return the value that was previously saved. Can be null.
     * @throws IllegalArgumentException if the given class type is not supported
     */
    @Nullable
    @Override
    public <T> T retrieve(@NonNull String name, @NonNull Class<T> tClazz) throws IllegalArgumentException {
        if (!sp.contains(name)) {
            return null;
        }
        Object value;
        if (tClazz.isAssignableFrom(String.class)) {
            value = sp.getString(name, null);
        } else if (tClazz.isAssignableFrom(Boolean.class)) {
            value = sp.getBoolean(name, false);
        } else if (tClazz.isAssignableFrom(Long.class)) {
            value = sp.getLong(name, 0);
        } else if (tClazz.isAssignableFrom(Float.class)) {
            value = sp.getFloat(name, 0);
        } else if (tClazz.isAssignableFrom(Integer.class)) {
            value = sp.getInt(name, 0);
        } else {
            throw new IllegalArgumentException("The class type is not supported. Supported types are: String, Boolean, Long, Float and Integer.");
        }
        return tClazz.cast(value);
    }
}
