package com.auth0.android.verification;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.auth0.android.callback.BaseCallback;

import java.security.PublicKey;

interface KeyProvider {
    void getPublicKey(@Nullable String keyId, @NonNull BaseCallback<PublicKey, KeyProviderException> callback);
}
