package com.auth0.android.verification;

import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

class JwksDeserializer implements JsonDeserializer<List<Jwk>> {

    @Override
    public List<Jwk> deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        if (!json.isJsonObject() || json.isJsonNull()) {
            throw new JsonParseException("jwks json is not a valid json object");
        }

        List<Jwk> jwks = new ArrayList<>();
        JsonObject object = json.getAsJsonObject();
        JsonArray keys = object.getAsJsonArray("keys");
        for (JsonElement e : keys) {
            Jwk jwk = context.deserialize(e, Jwk.class);
            jwks.add(jwk);
        }
        return jwks;
    }

}


