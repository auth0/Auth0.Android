package com.auth0.android.authentication.storage

import android.content.Context
import android.content.SharedPreferences
import android.text.TextUtils

/**
 * An implementation of [Storage] that uses [android.content.SharedPreferences] in Context.MODE_PRIVATE to store the values.
 */
public class SharedPreferencesStorage @JvmOverloads constructor(
    context: Context,
    sharedPreferencesName: String = SHARED_PREFERENCES_NAME
) : Storage {
    private val sp: SharedPreferences
    override fun store(name: String, value: Long?) {
        if (value == null) {
            sp.edit().remove(name).apply()
        } else {
            sp.edit().putLong(name, value).apply()
        }
    }

    override fun store(name: String, value: Int?) {
        if (value == null) {
            sp.edit().remove(name).apply()
        } else {
            sp.edit().putInt(name, value).apply()
        }
    }

    override fun store(name: String, value: String?) {
        if (value == null) {
            sp.edit().remove(name).apply()
        } else {
            sp.edit().putString(name, value).apply()
        }
    }

    override fun store(name: String, value: Boolean?) {
        if (value == null) {
            sp.edit().remove(name).apply()
        } else {
            sp.edit().putBoolean(name, value).apply()
        }
    }

    override fun retrieveLong(name: String): Long? {
        return if (!sp.contains(name)) {
            null
        } else sp.getLong(name, 0)
    }

    override fun retrieveString(name: String): String? {
        return if (!sp.contains(name)) {
            null
        } else sp.getString(name, null)
    }

    override fun retrieveInteger(name: String): Int? {
        return if (!sp.contains(name)) {
            null
        } else sp.getInt(name, 0)
    }

    override fun retrieveBoolean(name: String): Boolean? {
        return if (!sp.contains(name)) {
            null
        } else sp.getBoolean(name, false)
    }

    override fun remove(name: String) {
        sp.edit().remove(name).apply()
    }

    private companion object {
        private const val SHARED_PREFERENCES_NAME = "com.auth0.authentication.storage"
    }

    /**
     * Creates a new [Storage] that uses [SharedPreferences] in Context.MODE_PRIVATE to store values.
     *
     * @param context               a valid context
     * @param sharedPreferencesName the preferences file name
     */
    init {
        require(!TextUtils.isEmpty(sharedPreferencesName)) { "The SharedPreferences name is invalid." }
        sp = context.getSharedPreferences(sharedPreferencesName, Context.MODE_PRIVATE)
    }
}