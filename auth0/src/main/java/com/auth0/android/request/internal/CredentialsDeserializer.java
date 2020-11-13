package com.auth0.android.request.internal;

import androidx.annotation.VisibleForTesting;

import com.auth0.android.result.Credentials;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import java.lang.reflect.Type;
import java.util.Date;

class CredentialsDeserializer implements JsonDeserializer<Credentials> {

    @Override
    public Credentials deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        if (!json.isJsonObject() || json.isJsonNull() || json.getAsJsonObject().entrySet().isEmpty()) {
            throw new JsonParseException("credentials json is not a valid json object");
        }

        JsonObject object = json.getAsJsonObject();
        final String idToken = context.deserialize(object.remove("id_token"), String.class);
        final String accessToken = context.deserialize(object.remove("access_token"), String.class);
        final String type = context.deserialize(object.remove("token_type"), String.class);
        final String refreshToken = context.deserialize(object.remove("refresh_token"), String.class);
        final Long expiresIn = context.deserialize(object.remove("expires_in"), Long.class);
        final String scope = context.deserialize(object.remove("scope"), String.class);
        Date expiresAt = context.deserialize(object.remove("expires_at"), Date.class);
        if (expiresAt == null && expiresIn != null) {
            expiresAt = new Date(getCurrentTimeInMillis() + expiresIn * 1000);
        }

        return createCredentials(idToken, accessToken, type, refreshToken, expiresAt, scope);
    }

    @VisibleForTesting
    long getCurrentTimeInMillis() {
        return System.currentTimeMillis();
    }

    @VisibleForTesting
    Credentials createCredentials(String idToken, String accessToken, String type, String refreshToken, Date expiresAt, String scope) {
        return new Credentials(idToken, accessToken, type, refreshToken, expiresAt, scope);
    }
}
