package com.auth0.android.authentication.storage;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

public abstract class Storage {

    public abstract void save(@NonNull String name, @Nullable String value);

    @Nullable
    public abstract String retrieve(@NonNull String name);
}
