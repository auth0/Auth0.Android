package com.auth0.android.request.internal;

import com.auth0.android.result.UserInfo;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Map;

class UserInfoDeserializer implements JsonDeserializer<UserInfo> {
    @Override
    public UserInfo deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        if (!json.isJsonObject() || json.isJsonNull() || json.getAsJsonObject().entrySet().isEmpty()) {
            throw new JsonParseException("user info json is not a valid json object");
        }

        JsonObject object = json.getAsJsonObject();
        final Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
        Map<String, Object> values = context.deserialize(object, mapType);
        return new UserInfo(values);
    }
}
