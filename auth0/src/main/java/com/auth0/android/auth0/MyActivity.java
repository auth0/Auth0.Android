package com.auth0.android.auth0;

import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.StringRes;

import com.auth0.android.auth0.lib.Auth0;
import com.auth0.android.auth0.lib.authentication.result.Credentials;

public class MyActivity extends Activity {

    private Auth0 account;
    private AuthCallback callback = new AuthCallback() {
        @Override
        public void onFailure(@NonNull Dialog dialog) {
            //Error!
        }

        @Override
        public void onFailure(@StringRes int titleResource, @StringRes int messageResource, Throwable cause) {
            //Error!
        }

        @Override
        public void onSuccess(@NonNull Credentials credentials) {
            //Got the credentials
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebAuthProvider.init(account)
                .useBrowser(true)
                .useCodeGrant(true)
                .withState("123456")
                .withConnection("twitter")
                .start(this, callback);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        final boolean handled = WebAuthProvider.resume(new AuthorizeResult(requestCode, resultCode, data));
        if (!handled) {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }
}