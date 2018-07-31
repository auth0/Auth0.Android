package com.auth0.android.authentication;

import android.support.annotation.Nullable;

import java.security.PublicKey;

interface KeyProvider {

    PublicKey getPublicKey(@Nullable String keyId) throws KeyProviderException;
}
