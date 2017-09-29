package com.auth0.android.request.internal;

import com.auth0.android.result.Credentials;
import com.auth0.android.result.UserProfile;
import com.auth0.android.util.JsonRequiredTypeAdapterFactory;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public abstract class GsonProvider {

    static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    public static Gson buildGson() {
        return new GsonBuilder()
                .registerTypeAdapterFactory(new JsonRequiredTypeAdapterFactory())
                .registerTypeAdapter(UserProfile.class, new UserProfileDeserializer())
                .registerTypeAdapter(Credentials.class, new CredentialsDeserializer())
                .setDateFormat(DATE_FORMAT)
                .create();
    }
}
