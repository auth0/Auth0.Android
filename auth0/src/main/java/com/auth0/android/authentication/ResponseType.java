package com.auth0.android.authentication;


import android.support.annotation.StringDef;

import java.lang.annotation.Retention;

import static com.auth0.android.authentication.ResponseType.CODE;
import static com.auth0.android.authentication.ResponseType.ID_TOKEN;
import static com.auth0.android.authentication.ResponseType.TOKEN;
import static java.lang.annotation.RetentionPolicy.SOURCE;

@Retention(SOURCE)
@StringDef({CODE, TOKEN, ID_TOKEN})
public @interface ResponseType {
    String CODE = "code";
    String TOKEN = "token";
    String ID_TOKEN = "id_token";
}
