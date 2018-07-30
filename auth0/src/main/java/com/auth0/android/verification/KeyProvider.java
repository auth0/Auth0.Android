package com.auth0.android.verification;

import android.support.annotation.Nullable;

import java.security.PublicKey;

interface KeyProvider {
    @Nullable
    PublicKey getPublicKey(@Nullable String keyId) throws KeyProviderException;
}
