package com.auth0.android.request.internal;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;

abstract class GsonBaseTest {

    static final String EMPTY_OBJECT = "src/test/resources/empty_object.json";
    static final String INVALID = "src/test/resources/invalid.json";


    Gson gson;

    <T> T pojoFrom(Reader json, TypeToken<T> typeToken) throws IOException {
        return gson.getAdapter(typeToken).fromJson(json);
    }

    <T> T pojoFrom(Reader json, Class<T> clazz) throws IOException {
        return gson.getAdapter(clazz).fromJson(json);
    }

    FileReader json(String name) throws FileNotFoundException {
        return new FileReader(name);
    }

}