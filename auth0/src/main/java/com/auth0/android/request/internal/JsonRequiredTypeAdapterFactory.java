package com.auth0.android.request.internal;

import androidx.annotation.NonNull;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.lang.reflect.Field;


class JsonRequiredTypeAdapterFactory implements TypeAdapterFactory {

    @NonNull
    public <T> TypeAdapter<T> create(@NonNull Gson gson, @NonNull final TypeToken<T> type) {

        final TypeAdapter<T> delegate = gson.getDelegateAdapter(this, type);

        return new TypeAdapter<T>() {

            public void write(JsonWriter out, T value) throws IOException {
                delegate.write(out, value);
            }

            public T read(JsonReader in) throws IOException {
                T pojo = delegate.read(in);

                Field[] fields = pojo.getClass().getDeclaredFields();
                for (Field f : fields) {
                    if (f.getAnnotation(JsonRequired.class) != null) {
                        try {
                            f.setAccessible(true);
                            if (f.get(pojo) == null) {
                                throw new JsonParseException(String.format("Missing required attribute %s", f.getName()));
                            }
                        } catch (IllegalAccessException ex) {
                            throw new JsonParseException(String.format("Missing required attribute %s", f.getName()));
                        }
                    }
                }
                return pojo;
            }
        }.nullSafe();
    }
}
