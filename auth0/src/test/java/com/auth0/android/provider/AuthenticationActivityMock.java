package com.auth0.android.provider;

import android.content.Context;
import android.content.Intent;
import android.support.annotation.NonNull;

/**
 * Created by lbalmaceda on 6/12/17.
 */

public class AuthenticationActivityMock extends AuthenticationActivity {

    private CustomTabsController customTabsController;
    private Intent deliveredIntent;

    @Override
    protected CustomTabsController createCustomTabsController(@NonNull Context context) {
        return customTabsController;
    }

    @Override
    protected void deliverSuccessfulAuthenticationResult(Intent result) {
        this.deliveredIntent = result;
        super.deliverSuccessfulAuthenticationResult(result);
    }

    public void setCustomTabsController(CustomTabsController customTabsController) {
        this.customTabsController = customTabsController;
    }

    public Intent getDeliveredIntent() {
        return deliveredIntent;
    }
}
