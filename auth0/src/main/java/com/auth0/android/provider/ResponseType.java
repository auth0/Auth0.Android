package com.auth0.android.provider;

import static com.auth0.android.provider.ResponseType.CODE;
import static com.auth0.android.provider.ResponseType.ID_TOKEN;
import static com.auth0.android.provider.ResponseType.TOKEN;
import static java.lang.annotation.RetentionPolicy.SOURCE;

import androidx.annotation.IntDef;
import java.lang.annotation.Retention;

@Retention(SOURCE)
@IntDef(value = {CODE, TOKEN, ID_TOKEN}, flag = true)
public @interface ResponseType {

    int CODE = 1;
    int TOKEN = 1 << 1;
    int ID_TOKEN = 1 << 2;
}
