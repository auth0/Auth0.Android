package com.auth0.android.request.internal;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.UserProfile;
import com.auth0.android.util.JsonRequiredTypeAdapterFactory;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

public abstract class GsonProvider {

    static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    @NonNull
    public static Gson buildGson() {
        Type jwksType = new TypeToken<Map<String, PublicKey>>() {
        }.getType();

        return new GsonBuilder()
                .registerTypeAdapterFactory(new JsonRequiredTypeAdapterFactory())
                .registerTypeAdapter(UserProfile.class, new UserProfileDeserializer())
                .registerTypeAdapter(Credentials.class, new CredentialsDeserializer())
                .registerTypeAdapter(jwksType, new JwksDeserializer())
                .setDateFormat(DATE_FORMAT)
                .create();
    }

    @VisibleForTesting
    static String formatDate(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT, Locale.US);
        return sdf.format(date);
    }
}
